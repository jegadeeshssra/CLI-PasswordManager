- StringDataRightTruncation: value too long for type character varying(17)
    - If you attempt to insert a string that exceeds this limit, the database truncates (cuts off) the excess characters.
    - If truncation is not allowed, the database raises the StringDataRightTruncation error instead of silently discarding data.

- TypeError: not all arguments converted during string formatting
        -  It typically means that the number of placeholders (%s, %d, etc.) in a string does not match the number of arguments provided.

- UnicodeDecodeError: 'utf-8' codec can't decode byte 0xb2 in position 0: invalid start byte