import sys
f = 'apps/api/src/services/report/service.py'
with open(f, 'r') as file:
    content = file.read()
content = content.replace('subject=parsed_email.subject if parsed_email else "N/A",', 'subject=(parsed_email.subject or "N/A") if parsed_email else "N/A",')
content = content.replace('sender=parsed_email.sender if parsed_email else "N/A",', 'sender=(parsed_email.sender or "N/A") if parsed_email else "N/A",')
content = content.replace('from_name=parsed_email.from_name if parsed_email else "N/A",', 'from_name=(parsed_email.from_name or "N/A") if parsed_email else "N/A",')
content = content.replace('from_address=parsed_email.from_address if parsed_email else "N/A",', 'from_address=(parsed_email.from_address or "N/A") if parsed_email else "N/A",')
content = content.replace('message_id=parsed_email.message_id if parsed_email else "N/A",', 'message_id=(parsed_email.message_id or "N/A") if parsed_email else "N/A",')
with open(f, 'w') as file:
    file.write(content)
