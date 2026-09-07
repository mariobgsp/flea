// The directory the current listing came from, watched so a change another program makes reaches the
// client without the user leaving the folder; see docs/protocol.md "changed". inotify rather than a
// poll because a poll wakes this process forever to learn that nothing happened.
use crate::backend::events::Event;
use crate::json::escape;
use std::io;
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

// Exactly the events that change what a listing says: which names are in it, and the size, date and
// mode its columns draw. A file growing under an open handle is not one of them, see AGENTS.md.
const IN_ATTRIB: u32 = 0x0000_0004;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
// Not IN_DELETE_SELF: the kernel removes the watch with the directory and sends IN_IGNORED whatever
// the mask says, so the bit was measured to change nothing and the removal is the event.
const IN_MOVE_SELF: u32 = 0x0000_0800;
const MASK: u32 = IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_MOVE_SELF;

// IN_CLOEXEC is O_CLOEXEC, so no thumbnailer child inherits this descriptor.
const IN_CLOEXEC: c_int = 0x0008_0000;
// One inotify_event is a watch descriptor, a mask, a cookie and a name length, then the name.
const EVENT_HEADER: usize = 16;
// Every event in one burst says the same thing to a client that re-reads the whole directory, so the
// thread pauses after a burst and a thousand writes cost one line instead of a thousand.
const COALESCE: Duration = Duration::from_millis(100);
// A batch size and not a limit: a read takes whole events only and leaves the rest queued for the
// next one, and the kernel's own drop happens at max_queued_events, which this does not bound.
const BUF: usize = 8192;

extern "C" {
    fn inotify_init1(flags: c_int) -> c_int;
    fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int;
    fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
}

// One directory at a time, plus the one a scan is currently reading. A negative fd is a box with no
// inotify left to give, and a negative descriptor is nothing watched.
pub struct Watch {
    fd: c_int,
    wd: c_int,
    incoming: c_int,
}

impl Watch {
    // A box that cannot hand out an inotify descriptor still gets a file manager: this reports no
    // watch on stderr rather than refusing to start, and the listing is then as live as 0.1.4's was.
    pub fn start(tx: Sender<Event>) -> Watch {
        let fd = unsafe { inotify_init1(IN_CLOEXEC) };
        if fd < 0 {
            eprintln!("flea: the open folder will not follow outside changes, inotify is unavailable");
            return Watch { fd: -1, wd: -1, incoming: -1 };
        }
        thread::spawn(move || pump(fd, tx));
        Watch { fd, wd: -1, incoming: -1 }
    }

    // Armed before a scan, alongside the watch the client is still on rather than in place of it, so
    // a scan that fails costs that directory nothing and a change during the scan is still seen.
    pub fn begin(&mut self, path: &Path) {
        self.drop_one(self.incoming);
        self.incoming = self.add(path);
    }

    // The new listing replaced the old, so the directory it replaced stops being watched. A re-list of
    // the SAME directory answers the descriptor it already had, so dropping it here would remove the
    // watch this just re-armed and leave the folder followed by nothing.
    pub fn commit(&mut self) {
        if self.incoming != self.wd {
            self.drop_one(self.wd);
        }
        self.wd = self.incoming;
        self.incoming = -1;
    }

    // The scan failed, so the listing did not move and neither did its watch.
    pub fn abandon(&mut self) {
        self.drop_one(self.incoming);
        self.incoming = -1;
    }

    pub fn stop(&mut self) {
        self.drop_one(self.wd);
        if self.incoming != self.wd {
            self.drop_one(self.incoming);
        }
        self.wd = -1;
        self.incoming = -1;
    }

    // A directory that cannot be watched is not an error the client can act on: it listed fine, and
    // the only consequence is the listing this build shipped before the watch existed.
    fn add(&self, path: &Path) -> c_int {
        if self.fd < 0 {
            return -1;
        }
        match CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(c) => unsafe { inotify_add_watch(self.fd, c.as_ptr(), MASK) },
            Err(_) => -1,
        }
    }

    fn drop_one(&self, wd: c_int) {
        if self.fd >= 0 && wd >= 0 {
            unsafe { inotify_rm_watch(self.fd, wd) };
        }
    }

    // A directory this box could have watched and did not, which is the only case worth a sentence
    // per listing: with no inotify instance at all, Watch::start already said so once at startup.
    pub fn refused(&self) -> bool {
        self.fd >= 0 && self.wd < 0
    }

    // A removed watch's own IN_IGNORED is delivered after inotify_rm_watch returns, so a burst is
    // this directory's only while its descriptor still matches; without this every navigation would
    // answer one changed line for the directory it had just arrived in.
    pub fn is_current(&self, wd: i32) -> bool {
        self.wd >= 0 && wd == self.wd
    }
}

// Sample input: one 16 byte header then the name, wd 1, mask 0x00000100 (IN_CREATE), cookie 0,
// len 16, "NEWFILE.txt\0\0\0\0\0".
fn pump(fd: c_int, tx: Sender<Event>) {
    let mut buf = [0u8; BUF];
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, BUF) };
        if n < 0 {
            let failure = io::Error::last_os_error();
            // A signal can cut a blocking read short, which is not the descriptor going away.
            if failure.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("flea: the open folder stopped following outside changes, the inotify read failed: {}", failure);
            return;
        }
        // A closed descriptor ends the thread; the loop keeps running without a watch.
        if n == 0 {
            return;
        }
        for wd in descriptors(&buf[..n as usize]) {
            if tx.send(Event::Changed(wd)).is_err() {
                return;
            }
        }
        thread::sleep(COALESCE);
    }
}

// Which watches this burst touched, each named once. Nothing past the descriptor is read, because
// the loop only has to know whether the burst belongs to the directory it is listing now.
fn descriptors(buf: &[u8]) -> Vec<i32> {
    let mut out: Vec<i32> = Vec::new();
    let mut at = 0;
    while at + EVENT_HEADER <= buf.len() {
        let wd = i32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        let len = u32::from_ne_bytes([buf[at + 12], buf[at + 13], buf[at + 14], buf[at + 15]]) as usize;
        if !out.contains(&wd) {
            out.push(wd);
        }
        // inotify hands back whole events only, so this can only overshoot on a buffer that did not
        // come from one; the condition above is the bound that keeps the indexing inside the slice.
        at += EVENT_HEADER + len;
    }
    out
}

// The one unsolicited line on the wire: the client asked for a listing, and this says the directory
// that listing came from is no longer what it answered with. path is that directory, so a client
// that has since moved can tell whose notification it is holding.
pub fn changed_line(path: &Path) -> String {
    format!(r#"{{"t":"changed","path":"{}"}}"#, escape(&path.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample input: two events on watch 3, one carrying a 16 byte name and one carrying none.
    fn event(wd: i32, name: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&wd.to_ne_bytes());
        out.extend_from_slice(&IN_CREATE.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        out.extend_from_slice(name);
        out
    }

    #[test]
    fn one_event_names_its_watch() {
        assert_eq!(descriptors(&event(3, b"a.txt\0\0\0")), vec![3]);
    }

    #[test]
    fn a_burst_names_each_watch_once() {
        let mut buf = event(3, b"a.txt\0\0\0");
        buf.extend(event(3, b""));
        buf.extend(event(4, b"b.txt\0\0\0"));
        assert_eq!(descriptors(&buf), vec![3, 4]);
    }

    // Not a shape inotify produces: it pins the bound, so a length running past the slice cannot panic.
    #[test]
    fn a_truncated_tail_ends_the_walk() {
        let mut buf = event(3, b"a.txt\0\0\0");
        buf.extend(event(4, b"this name did not fit"));
        buf.truncate(buf.len() - 4);
        assert_eq!(descriptors(&buf), vec![3, 4]);
    }

    #[test]
    fn a_short_buffer_names_nothing() {
        assert_eq!(descriptors(&[0u8; 8]), Vec::<i32>::new());
    }

    #[test]
    fn nothing_is_current_before_a_directory_is_followed() {
        let w = Watch { fd: -1, wd: -1, incoming: -1 };
        assert!(!w.is_current(-1));
        assert!(!w.is_current(1));
    }

    // These build a Watch with no descriptor, so add and drop_one are no-ops: what they pin is which
    // descriptor the bookkeeping calls current, and tests/protocol.sh pins what the syscalls do.
    #[test]
    fn an_abandoned_scan_leaves_the_current_watch_alone() {
        let mut w = Watch { fd: -1, wd: 7, incoming: -1 };
        w.begin(Path::new("/tmp"));
        w.abandon();
        assert!(w.is_current(7));
    }

    // And one that succeeds hands the listing over to the descriptor the scan was armed with.
    #[test]
    fn a_committed_scan_takes_over_from_the_old_watch() {
        let mut w = Watch { fd: -1, wd: 7, incoming: 9 };
        w.commit();
        assert!(w.is_current(9));
        assert!(!w.is_current(7));
    }

    #[test]
    fn the_changed_line_names_its_directory() {
        assert_eq!(
            changed_line(Path::new("/tmp/a \"b\"")),
            r#"{"t":"changed","path":"/tmp/a \"b\""}"#
        );
    }
}
