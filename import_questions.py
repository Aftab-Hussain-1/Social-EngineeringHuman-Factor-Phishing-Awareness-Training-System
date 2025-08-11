
import csv
from app import create_app, db
from app.models import Question

def import_questions_from_csv():
    app = create_app()
    
    with app.app_context():
        # Clear existing questions (optional - remove this if you want to keep existing ones)
        Question.query.delete()
        
        # CSV data as string (from your file)
        csv_data = """1	You receive an email asking you to reset your company password. The link looks suspicious. What should you do?	Click the link to reset quickly	Forward the email to IT/security team	Ignore and delete the email	Reply and ask if it's real	B
2	What is the best way to create a secure password?	Use your birthday and favorite color	Use a long, complex mix of characters	Reuse your old password	Use "password123"	B
3	You find a USB drive in the office parking lot. What should you do?	Plug it into your computer to see what's inside	Give it to a coworker	Hand it over to the IT department	Take it home	C
4	Which of the following is an example of phishing?	An IT update from your company domain	An email from HR asking for a survey	An email with a mismatched sender asking for login info	A system notification	C
5	You receive a call from someone claiming to be your bank asking for OTP. What should you do?	Give them the OTP to verify	Hang up and call the official number	Ask them to email you	Tell them your full account details	B"""
        
        # Split into lines and process each line
        lines = csv_data.strip().split('\n')
        
        # Track unique questions to avoid duplicates
        unique_questions = set()
        added_count = 0
        
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 6:
                    question_id = parts[0]
                    question_text = parts[1]
                    option_a = parts[2]
                    option_b = parts[3]
                    option_c = parts[4]
                    option_d = parts[5]
                    correct_option = parts[6]
                    
                    # Create a unique identifier for the question
                    question_signature = (question_text, option_a, option_b, option_c, option_d)
                    
                    # Only add if this exact question hasn't been seen before
                    if question_signature not in unique_questions:
                        unique_questions.add(question_signature)
                        
                        # Create new question
                        new_question = Question(
                            text=question_text,
                            option_a=option_a,
                            option_b=option_b,
                            option_c=option_c,
                            option_d=option_d,
                            correct_option=correct_option
                        )
                        
                        db.session.add(new_question)
                        added_count += 1
        
        # Commit all changes
        db.session.commit()
        print(f"Successfully imported {added_count} unique questions to the database!")
        
        # Show total questions in database
        total_questions = Question.query.count()
        print(f"Total questions in database: {total_questions}")

if __name__ == '__main__':
    import_questions_from_csv()
