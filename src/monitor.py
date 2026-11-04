with open("tests/sample_auth.log", "r") as file:        
    counter = 0
    failed_attempts = {}
    threshold = 5
    for line in file:     #writing the loop allows for the program to read the file one line at a time instead of storing the entire file into a variable
        if "Failed password" in line:  #only prints the failed log in attempts from the file
            #print(line.strip())
            counter += 1        #counts the amount of failed login attempts
            words = line.split()  #splits string into a list of words
            from_index = words.index("from")    #"from" is the word that appears before the ip address for all the lines so using the .index() gives us the index of where "from" is at
            ip_address = words[from_index + 1]  #since we know "from" appears right before ip and the index() gives us an int when indexing the word list from_index + 1 gives us the index of the ip address
            #print(ip_address)
            if ip_address in failed_attempts:       #checks to see if the ip_address is already in the dict and if it is just increase the value by and and if it isnt it assigns 1 to its value
                failed_attempts[ip_address] += 1
            else:
                failed_attempts[ip_address] = 1            

for tracked_ip, count in failed_attempts.items():  #items() helps seperate the key and value from the dict and we print it out
    print(tracked_ip, count)
    if count >= threshold:
        print(f"ALERT {tracked_ip} has {count} failed login attempts!")

print(f"{counter} failed login attempts")
print(failed_attempts)



#failed_attempts = {}
#failed_attempts[192.0.2.100] = 1
#failed_attempts[192.0.2.101] = 2

#failed_attempts[192.0.2.100] = 3

#print(failed_attempts)

#if ip_address in failed_attempts:
#    failed_attempts[ip_address] += 1
#else:
#   failed_attempts[ip_address] = 1