#[cfg(test)]
mod tests {
    use capfile::Error;

    #[test]
    fn test_error_types() {
        let err = Error::parse(100, "test error");
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains("100"),
            "Error should contain offset: {}",
            err_str
        );
        assert!(
            err_str.contains("test error"),
            "Error should contain message: {}",
            err_str
        );

        let err = Error::truncated(10, 5);
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains("Truncated"),
            "Error should contain Truncated: {}",
            err_str
        );

        let err = Error::InvalidMagic(0x12345678);
        let err_str = format!("{:?}", err);
        assert!(
            err_str.contains("Invalid"),
            "Error should contain Invalid: {}",
            err_str
        );
    }
}
