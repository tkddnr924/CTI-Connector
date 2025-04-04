class PLBEml:
    def __init__(
        self, 
        file_name, 
        message_id, 
        date, 
        subject, 
        from_, 
        to_, 
        cc_,
        suspicious_link,
        suspicious_file,
        md5
    ) -> None:
    
        self.file_name = file_name
        self.message_id = message_id
        self.date = date
        self.subject = subject
    
        self.from_ = from_
        self.to_ = to_
        self.cc_ = cc_

        self.suspicious_link = suspicious_link
        self.suspicious_file = suspicious_file
        
        self.md5 = md5
        
    def __repr__(self) -> str:
        return f"<MY_EML {self.file_name} | {self.message_id}>"

    