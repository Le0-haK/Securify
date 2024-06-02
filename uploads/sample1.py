import os

user_input = input("Enter a command: ")
p = os.popen(user_input)
output = p.read()
print(output)

user_input = input("Enter a command: ")
os.spawnv(os.P_NOWAIT, '/bin/ls', ['ls', user_input])

def vulnerable_function1(user_input):
    subprocess.call("grep -R {}.".format(user_input), shell=True)

def vulnerable_function2(user_input):
    subprocess.run(["bash", "-c", user_input], shell=True)    

pid = os.spawn(os.P_NOWAIT, "/bin/ls", ["ls", "-l"])    