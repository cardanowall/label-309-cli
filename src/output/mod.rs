//! Output rendering: the human-readable verify transcript and the inbox-list
//! table. Machine output (`--json`) is emitted by the commands directly.

pub mod render_human;
pub mod render_inbox_list;

pub use render_human::render_human_report;
pub use render_inbox_list::render_inbox_list_human;
