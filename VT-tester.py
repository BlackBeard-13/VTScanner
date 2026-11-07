import sys
##functions held in seperate script to build on later on
from Functions.vtfunctions  import file_option, url_option, check_key
from Functions.utils import print_banner


### PLEASE N0TE! the functions called will need the use to add the Virus Total API key given for signing up on virus total


def main(max_tries=3):
    #Print Banner because why not
    print_banner()
   #Make sure the API key it valid and set before proceeding
    if not check_key():
        sys.exit(1) 

   
    #create the options that will pull the two functions
    choose_scan = {
     "1": file_option,
     "2": url_option
    }

    #Executes the program and directs which function to choose based on the users choice. 
    #If there isn't a valid choice in 3 tries it will exit
    for attempt in range(1, max_tries +1):
        ##present the options to the user two choose, once 1 or 2 is enters we will proceed to call the correct function, 3 will exit
        option = input("""
    >>> Please select an option: <<<
         1. File Name
         2. URL Name
         3. Exit Program
         Which Option: """).strip()
        action = choose_scan.get(option)
        if option == "3":
            print("Goodbye!")
            return None
        elif action:
            action()
            break
        else:
            print("Invalid Choice")

# makes sure the program can on be trigger when directly run
if __name__ == "__main__":
     main()