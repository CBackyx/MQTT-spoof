import os

test_message = ""

for i in range(32755):
    test_message = test_message + "a"

os.system("mosquitto_pub -t test_topic -m {} -p 1883".format(test_message))