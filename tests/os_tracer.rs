//! The real file read behind the library check (`OsTracer::file_image`). The
//! scripted tracers cover its callers; these tests run the real calls.

use std::fs;
use std::os::unix::fs::MetadataExt;

use leakgc::supervisor::{OsTracer, Tracer};

#[test]
fn file_image_returns_the_inode_and_the_bytes_of_the_file() {
    let exe = std::env::current_exe().expect("locate the test executable");
    let path = exe.to_str().expect("UTF-8 path");

    let (inode, bytes) = OsTracer.file_image(path).expect("read the executable");

    assert_eq!(inode, fs::metadata(path).expect("stat").ino());
    assert_eq!(bytes, fs::read(path).expect("read"));
}

#[test]
fn file_image_of_a_missing_file_is_an_error() {
    assert!(
        OsTracer
            .file_image("/nonexistent/leakgc/library.so")
            .is_err()
    );
}

#[test]
fn file_image_of_a_directory_is_an_error() {
    assert!(OsTracer.file_image(env!("CARGO_MANIFEST_DIR")).is_err());
}
