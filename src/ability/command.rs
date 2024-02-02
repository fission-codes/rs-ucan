pub trait Command {
    const COMMAND: &'static str;
}

// NOTE do not export // FIXME move to internal?
pub(super) trait ToCommand {
    fn to_command(&self) -> String;
}

impl<T: Command> ToCommand for T {
    fn to_command(&self) -> String {
        T::COMMAND.to_string()
    }
}
