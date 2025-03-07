# Security-701-Acronym-Quiz

Security+ is an industry recognized foundational cybersecurity certification that verifies candidates have the knowledge necessary to start a career in IT security. While many Security+ study resources exist, few focus specifically on the numerous acronyms that may appear on the exam. To fill this void in my study routine, I coded this Python program with GitHub Copilot's assistance to quiz myself on Security+ acronyms. By using this program daily leading up to the exam, I got much more familiar with the acronyms to the point that I didn't encounter an acronym I didn't know on the exam.

# Features

The program has two modes:
- Mode 1: Shows the definition and the user enters the correct acronym
- Mode 2: Shows the acronym and the user enters the correct definition

After the user enters 1 or 2 for the mode, the program will ask how many questions to ask:
- Enter 'all' to get quizzed on the entire acronym dictionary
- Enter a number to get quizzed on that many random acronyms

When the quiz starts, the program will display feedback on the user's answer:
- Correct answers: The program displays a "Correct!" message
- Incorrect answers: The program displays the correct answer. 

After the quiz ends, the program will:
- Display the user's score
- Ask if they would like to get quizzed on incorrect answers

# Repository Contents
- acronym-dictionary.txt – A dictionary of Security+ acronyms and their definitions based on the exam objectives.
- acronym-quiz.py – The Python program that runs the quiz.
