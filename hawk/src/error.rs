
error_chain! {
    errors {
        HeaderParseError {
            description("Unparseable Hawk header")
        }
    }

    foreign_links {
        Io(::std::io::Error);
    }
}
