password = input("Enter Your Password: ")

special = set("@#$%^&*()_+\"'?- ")
uppercase = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
digits = set("0123456789")

score = 0

if len(password) > 12:
    score += 2
elif len(password) > 8:
    score += 1
else:
    print("Weak Password")

if any(char in special for char in password):
    score += 1

if any(char in uppercase for char in password):
    score += 1

if any(char in digits for char in password):
    score += 1

if score <= 1:
    print("BAD Password")
elif score == 2:
    print("Good Password")
elif score == 3:
    print("Excellent Password")
elif score == 4:
    print("Very Excellent Password")
elif score == 5:
    print("Great Password")
elif score == 6:
    print("Semi perfect Password")
elif score == 7:
    print("Perfect Password")
elif score == 8:
    print("Very perfect Password")
elif score == 9:
    print("Mastered Password")
else:
    print("prefectionist Password")
