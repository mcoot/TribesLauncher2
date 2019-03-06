// use tribeslauncher::config;
use tribeslauncher::injector;
// use tribeslauncher::updater;

fn main() {
    let query = injector::ProcessQuery::ProcName("notepad.exe");

    injector::perform_injection(query, "testdll.dll").expect("failed");
    // updater::perform_update("https://raw.githubusercontent.com/mcoot/tamodsupdate/release")
    //     .expect("failed update");
}