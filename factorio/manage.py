import sys
import threading
import time
import os
import signal


# Find server with given name
# struct ServerData * find_server(char * name)
def find_server(name):
    server = {}
    return server


# Function to write data using thread safe methods
# char * send_threaded_chat(char * name, char * message)
def send_threaded_chat(name, message):
    return "Not Yet Implemented"


# Function to log chat using thread safe methods
# char * log_chat(char * name, char * message)
def log_chat(name, message):
    return "Not Yet Implemented"


# Get the status of a server
# char * get_server_status(char * name)
def get_server_status(name):
    return "Not Yet Implemented"


# Function to be called by threads in order to monitor input
# void * input_monitoring(void * server_ptr)
def input_monitoring(server_ptr):
    return "Not Yet Implemented"


# Contrary to what the name suggests, this function can launch either the bot or a server successfully
# This will return a struct containing the name of the server
# The struct also contains the file descriptors relating to the input and output of the server
# char * launch_server(char * name, char ** args, char * logpath)
def launch_server(name, args, logpath):
    return "Not Yet Implemented"


# Start a server
# char * start_server(char * name, char * input)
def start_server(name, input):
    return "Not Yet Implemented"


# Stop a currently running server
# char * stop_server(char * name)
def stop_server(name):
    return "Not Yet Implemented"


# void stop_all_servers()
def stop_all_servers():
    return  # "Not Yet Implemented"


# void * bot_ready_watch(void * vbot)
def bot_ready_watch(vbot):
    return  # "Not Yet Implemented"


# void launch_bot()
def launch_bot():
    return  # "Not Yet Implemented"


# void server_crashed(struct ServerData * server)
def server_crashed(server):
    return  # "Not Yet Implemented"


# void * heartbeat()
# Uses global `server_list` to know who to send messages to
class Heartbeat (threading.Thread):
    def run(self):
        while True:
            send_threaded_chat("bot", "heartbeat$")
            for server in server_list:
                send_threaded_chat(server, "/silent-command local heartbeat = true\n")
            time.sleep(15)


# int main()
def main():
    # Initial setup of variables
    # need to work out scope for these, do they all need to be global etc?
    # servers = 0
    global server_list
    server_list = []
    # thread_list = []
    currently_running = 0
    # bot_ready = 0

    # pthread_attr_init(&thread_attr);
    # pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
    #
    # Redirect certain signals to perform other functions
    # if (signal(SIGINT, stop_all_servers) == SIG_ERR) fprintf(stderr, "Failure to ignore interrupt signal.\n"); //Safe shutdown of all servers
    # if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) fprintf(stderr, "Failure to ignore broken pipe signal.\n"); //Crash detection

    # Launch the bot
    launch_bot()

    # //Create the heartbeat, also for improved crash detection
    # pthread_t heartbeat_thread;
    # pthread_create(&heartbeat_thread, &thread_attr, heartbeat, (void *) NULL);
    heartbeat_thread = Heartbeat()
    heartbeat_thread.start()

    for line in sys.stdin:
        servername, new_input = line.split("$", 1)
        # not sure if we need to detect \n and replace with \0 here in new_input
        # Checks for command
        if new_input.find("$") != -1:
            # Start command
            new_input, server_args = new_input.split("$", 1)
            if start_server(servername, server_args) == "Server Running":
                print("Server {} Already Running".format(servername), file=sys.stdout)
                continue
            print("Server {} Started".format(servername), file=sys.stdout)
            send_threaded_chat("bot", "{}$**[ANNOUNCEMENT]** Server has started!".format(servername))
            currently_running += 1
        elif new_input == "stop":
            # Stop command
            if stop_server(servername) == "Server Not Running":
                print("Server {} Not Running".format(servername), file=sys.stdout)
                continue
            print("Server {} Stopped".format(servername), file=sys.stdout)
            currently_running -= 1
            send_threaded_chat("bot", "{}$**[ANNOUNCEMENT]** Server has stopped!".format(servername))
            if currently_running == 0:
                break
        elif new_input == "status":
            # Status command
            print(get_server_status(servername), file=sys.stdout)
        elif new_input == "force_close":
            # Force close a server
            # If server is not running
            if get_server_status(servername) == "Server Stopped":
                continue
            if get_server_status(servername) == "Server Does Not Exist":
                continue

            # Get the server to shut down
            server = find_server(servername)

            os.kill(server.pid, signal.SIGKILL)  # Send SIGKILL to the server, forcing an immediate shutdown

            print("Server {} Stopped".format(servername), file=sys.stdout)
            currently_running -= 1
            send_threaded_chat("bot", "{}$**[ANNOUNCEMENT]** Server has stopped!".format(servername))
            if currently_running == 0:
                break
        else:
            # Chat or in-game command
            send_threaded_chat(servername, new_input + '\n')
            if "[WEB]" in new_input:
                log_chat(servername, new_input[new_input.find("[WEB]"):])

    # Shut down the bot, giving it time to finish whatever action it is doing
    time.sleep(5)

    bot = server_list[0]
    os.kill(bot.pid, signal.SIGINT)
    os.waitpid(bot.pid, 0)
    # pthread_join(thread_list[0], NULL);
    # close(bot->input); //Close input pipe
    # close(bot->output); //Close output pipe

    # Exit successfully
    return 0

server_list = []
if __name__ == "__main__":
    sys.exit(main())
