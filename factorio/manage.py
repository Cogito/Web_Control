import sys
import errno
import threading
import time
import os
from signal import signal, SIGINT, SIGPIPE, SIG_IGN, SIGKILL
import re
import datetime

#changes
# server_list is a dict containing servers indexed by name, and does not contain the bot
# bot contains info about the bot

server_list = {}
thread_list = {}
bot_ready = 0
currently_running = 0


class Server:
    def __init__(self, pid, name, input, output, mutex, status, logfile, chatlog, chat_mutex):
        self.pid = pid  # The process id of the server, used to send SIGINT (CTRL-C)
        self.name = name  # Server Name
        self.input = input  # Overwritten STDIN
        self.output = output  # Overwritten STDOUT
        self.mutex = mutex  # Thread safety
        self.status = status  # Started or Stopped
        self.logfile = logfile  # Location of logfile to write to
        self.chatlog = chatlog  # Location of chatlog to write to
        self.chat_mutex = chat_mutex  # Mutex for chatlog protection


# Find server with given name
# struct ServerData * find_server(char * name)
def find_server(name):
    if name in server_list:
        return server_list[name]
    else:
        return None


# Function to write data using thread safe methods
# char * send_threaded_chat(char * name, char * message)
def send_threaded_chat(name, message):
    # Get the server that data is being sent to
    sendto = find_server(name)
    if not sendto:
        return "Server Not Running"
    if sendto.status == "Stopped":
        return "Server Not Running"

    # Attempt to lock the mutex - If another thread is currently writing to this place, the code will wait here
    sendto.mutex.acquire()

    # In case of crashes
    if sendto.status == "Stopped":
        return "Server Crashed"

    # Write data, with added error checking for crash detection
    try:
        output = os.fdopen(os.dup(sendto.input), "a")
        output.write(message)
    except IOError as e:
        if e.errno == errno.EPIPE:
            server_crashed(sendto)
            return "Failed"

    # Unlock the mutex so that another thread can send data to this server
    sendto.mutex.release()

    return "Successful"


# Function to log chat using thread safe methods
# char * log_chat(char * name, char * message)
def log_chat(name, message):
    # Get the server that data is being sent to
    sendto = find_server(name)
    if not sendto:
        return "Server Not Running"
    if sendto.status == "Stopped":
        return "Server Not Running"

    # Strip trailing characters if present
    message = message.strip()

    # Set up the timestamp
    # YYYY-MM-DD HH:MM:SS
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Set up timestamped message, also prefixes chats coming in from servers with [CHAT]
    chat = 1
    if "[DISCORD]" in message:
        chat = 0
    if "[WEB]" in message:
        # If this message comes from the webserver, send it to the bot
        if message[-1] == ')' and message[-2] == '"':
            message = message[:-2]
        send_threaded_chat("bot", "{}${}\n".format(name, message))
        chat = 0
    if "[PUPDATE]" in message:
        chat = 0
    if chat == 1:
        output_message = "{} [CHAT] {}\r\n".format(timestamp, message)
    else:
        output_message = "{} {}\r\n".format(timestamp, message)

    # Attempt to lock the mutex - If another thread is currently writing to this place, the code will wait here
    sendto.chat_mutex.acquire()

    # Write data
    with open(sendto.chatlog, "a") as output:
        output.write(output_message)

    # Unlock the mutex so that another thread can send data to this server
    sendto.chat_mutex.release()

    return "Successful"


# Get the status of a server
# char * get_server_status(char * name)
def get_server_status(name):
    # Check to see if a server is running or not
    server = find_server(name)
    if not server:
        return "Server Does Not Exist"
    elif server.status == "Stopped":
        return "Server Stopped"
    elif server.status == "Restarting":
        return "Bot Restarting"
    else:
        return "Server Running"


# Function to be called by threads in order to monitor input
# void * input_monitoring(void * server_ptr)
def input_monitoring(server):
    global bot_ready
    input_from_server = os.fdopen(server.output, "r")  # Begin monitoring the pipe
    if server.name != "bot":
        # If Factorio server, create the logfile
        logfile = open(server.logfile, "a")
    while True:
        data = input_from_server.readline(2001)
        if not data or data[0] == '\n':
            # This should only get called when the server shuts down
            break

        if server.name != "bot" and " [CHAT] " not in data and " (shout):" not in data:
            logfile.write("{}\r\n".format(data))

        if "$" in data and (" [CHAT] " not in data and " (shout):" not in data) or server.name == "bot":
            # The format of the data is "servername$new_data"
            # Handles the rare occasion a chat message will have a '$' inside it
            servername, new_data = data.split("$", 1)
            new_data = new_data.strip()  # if (strchr(new_data,'\n') != NULL) new_data[strchr(new_data,'\n') - new_data] = '\0';
            if servername == "restart" and server.name == "bot":
                # Bot wants to restart
                server.mutex.acquire()  # Lock the mutex to prevent the bot from being used before it's ready
                bot_ready = 0
                server.status = "Restarting"
                os.kill(server.pid, SIGINT)
                os.waitpid(server.pid, 0)
                input_from_server.close()
                server.input.close()
                launch_bot()
                input_from_server = os.fdopen(server.output, "r")
                server.mutex.release()
            elif servername == "ready" and server.name == "bot":
                # Bot startup is complete, it is ready to continue
                bot_ready = 1
            elif servername == "DEBUG":
                # Handle debug messages
                print("{}\n".format(new_data), file=sys.stderr)
            elif servername == "chat":
                # Handle Articulating's Chat Program
                chat_args = re.split("[,\n\t]+", new_data.strip())
                message =  "/silent-command push_message('{}','{}','{}')\n".format(chat_args[0], chat_args[1], chat_args[2])
                for _, server in server_list.items():
                    if server.status == "Started":
                        send_threaded_chat(server.name, message)
            elif servername == "PLAYER":
                # This is a player update, used for the bot to keep track of PvP Player Teams
                message = "PLAYER${}${}\n".format(server.name, new_data)
                player_args = re.split("[,\n\t]+", new_data.strip())

                if player_args[0] == "join":
                    player_announcement = "[PUPDATE] {} has joined the server [{}]".format(player_args[2], player_args[3])
                elif player_args[0] == "leave":
                    player_announcement = "[PUPDATE] {} has left the server [{}]".format(player_args[2], player_args[3])
                elif player_args[0] == "force":
                    player_announcement = "[PUPDATE] {} has changed forces to {}".format(player_args[2], player_args[3])
                elif player_args[0] == "die":
                    player_announcement = "[PUPDATE] {} was killed [{}]".format(player_args[2], player_args[3])
                elif player_args[0] == "respawn":
                    player_announcement = "[PUPDATE] {} has respawned [{}]".format(player_args[2], player_args[3])
                elif player_args[0] != "update":
                    continue

                log_chat(server.name, player_announcement)
                send_threaded_chat("bot", message)
            elif servername == "admin":
                if server.name == "bot":
                    # Bot is sending a command or announcement to a server
                    actual_server_name, command = new_data.split("$", 1)
                    command = command + "\n"
                    if actual_server_name == "all":
                        for server_name in server_list:
                            # if server.status == "Started":  # Should this be here as it is in other places?
                            send_threaded_chat(server_name, command)
                    else:
                        send_threaded_chat(actual_server_name, command)
                else:
                    # Admin Warning System is being sent back to the bot
                    message = "admin${}${}\n".format(server.name, new_data)
                    send_threaded_chat("bot", message)
            elif servername == "output":
                message = "output$(%s)%s\n".format(server.name, new_data)
                send_threaded_chat("bot", message)
            elif servername == "query":
                message = "query%s\n".format(new_data)
                send_threaded_chat("bot", message)
            elif servername == "PVPROUND":
                message = "PVPROUND$%s$%s\n".format(server.name, new_data)
                send_threaded_chat("bot", message)
            elif server.name == "bot":
                if servername == "PVP":
                    # Bot is sending chat to a PvP server through default chat
                    actual_server_name, force_name, message_to_send = new_data.split("$", 2)

                    log_chat(actual_server_name, message_to_send)
                    message = "/silent-command if game.forces['{}'] then game.forces['{}'].print('{}') end\n".format(force_name, force_name, message_to_send)
                    send_threaded_chat(actual_server_name, message)
                else:
                    # Bot is sending chat to a normal server through default chat
                    log_chat(servername, new_data)
                    message = "/silent-command game.print('{}')\n".format(new_data)
                    send_threaded_chat(servername, message)
        elif " [CHAT] " in data and "[DISCORD]" not in data:
            # Server is sending chat through default chat, relay it to bot
            # Also includes check to prevent echoing
            new_data = data[data.find(" CHAT ") + len(" CHAT "):]
            log_chat(server.name, new_data)
            message = "{}${}\n".format(server.name, new_data)
            send_threaded_chat("bot", message)
        elif " (shout):" in data and "[DISCORD]" not in data:
            log_chat(server.name, data)
            message = "{}${}\n".format(server.name, data)
            send_threaded_chat("bot", message)
    # After server is closed, close file streams

    if server.name != "bot":
        # If Factorio server, close the logfile
        logfile.close()

    input_from_server.close()


# Contrary to what the name suggests, this function can launch either the bot or a server successfully
# This will return a struct containing the name of the server
# The struct also contains the file descriptors relating to the input and output of the server
# char * launch_server(char * name, char ** args, char * logpath)
def launch_server(name, args, logpath):

    server_status = get_server_status(name)

    # Check to see if server is already running
    if server_status == "Server Running":
        return "Server Running"

    # Create logfile filepath, if this is not the bot
    if name != "bot":
        # "/var/www/factorio/name/screenlog.0"
        logfile = "{logpath}/screenlog.0".format(logpath=logpath)
    else:
        logfile = "bot"

    # Create chatlog filepath, if this is not the bot
    if name != "bot":
        # // "/var/www/factorio/name/chatlog.0"
        chatlog = "{logpath}/chatlog.0".format(logpath=logpath)
    else:
        chatlog = "bot"

    # Create pipes
    child_in, parent_out = os.pipe()
    parent_in, child_out = os.pipe()
    pid = os.fork()
    if pid < 0:
        print("Failure to fork process.", file=sys.stderr)
        clean_exit(1)
    elif pid == 0:
        # Child Process (Server)
        os.dup2(child_in, sys.stdin.fileno())
        os.close(child_in)
        os.close(parent_out)
        os.dup2(child_out, sys.stdout.fileno())
        os.close(child_out)
        os.close(parent_in)
        os.execvp(args[0], args)
    else:
        # Only parent process reaches this point
        # Adds server to server_list, and creates new thread for monitoring
        os.close(child_in)
        os.close(child_out)
        if server_status == "Server Does Not Exist":
            server = Server(
                pid=pid,
                name=name,
                input=parent_out,
                output=parent_in,
                mutex=threading.Lock(),
                status="Started",
                logfile=logfile,
                chatlog=chatlog,
                chat_mutex=threading.Lock(),
            )
            server_list[server.name] = server
            thread_list[server.name] = threading.Thread(target=input_monitoring, args=(server,), daemon=True)
            thread_list[server.name].start()

            return "New Server Started"
        else:
            server = find_server(name)
            server.pid = pid
            server.input = parent_out
            server.output = parent_in
            server.logfile = logfile
            server.chatlog = chatlog
            if server.status != "Restarting":
                thread_list[server.name] = threading.Thread(target=input_monitoring, args=(server,), daemon=True)
                thread_list[server.name].start()
            else:
                thread_list[server.name] = threading.Thread(target=bot_ready_watch, args=(server,), daemon=True)
                thread_list[server.name].start()
            server.status = "Started"

            return "Old Server Restarted"


# Start a server
# char * start_server(char * name, char * input)
def start_server(name, input_args):
    args = re.split("[,\n\t]+", input_args.strip())
    # Process of setting up the arguments for the execvp() call
    launchargs = []
    offset = 0

    launchargs.append("TEMP")
    if args[0] == "true":
        launchargs.append("--start-server-load-latest")
    else:
        launchargs.extend(["--start-server", args[1]])
        offset = offset + 1
    launchargs.extend(["--port", args[1 + offset]])
    launchargs.extend(["-c", "{}/config/config.ini".format(args[2 + offset])])
    launchargs.extend(["--server-setting", "{}/server-settings.json".format(args[2 + offset])])
    launchargs[0] = args[3 + offset]

    result = launch_server(name, launchargs, args[2 + offset])
    return result


# Stop a currently running server
# char * stop_server(char * name)
def stop_server(name):
    # If server is not running
    if get_server_status(name) == "Server Stopped":
        return "Server Not Running"
    if get_server_status(name) == "Server Does Not Exist":
        return "Server Not Running"

    # Get the server to shut down
    server = find_server(name)

    os.kill(server.pid, SIGINT)  # Send CTRL-C to the server, should close pipes on server end
    os.waitpid(server.pid, 0)  # Wait for server to close
    thread_list[server.name].join()  # Wait for thread to terminate
    server.input.close()  # Close input pipe
    server.output.close()  # Close output pipe
    server.status = "Stopped"

    return "Server Stopped"


# void stop_all_servers()
def stop_all_servers():
    for _, server in server_list.items():
        stop_server(server.name)
        print("Server {} Shutdown".format(server.name), file=sys.stdout)
        send_threaded_chat("bot", "{}$**[ANNOUNCEMENT]** Server has stopped!".format(server.name))
    # Exit successfully
    clean_exit(0)


# void * bot_ready_watch(void * vbot)
def bot_ready_watch(bot):
    global bot_ready
    bot_input = os.fdopen(os.dup(bot.output), "r")
    while True:
        data = bot_input.readline(2001)
        if data == "ready$\n":
            break
    bot_ready = 1


# void launch_bot()
def launch_bot():
    global bot_ready
    launch_server("bot", ["node", "./3RaFactorioBot.js", ""], "bot")

    while bot_ready == 0:
        # Wait for the bot to reply that it's ready.
        time.sleep(1)


# void server_crashed(struct ServerData * server)
def server_crashed(server):
    global bot_ready
    global currently_running
    # The server has crashed
    server.input.close()  # Close input pipe
    server.output.close()  # Close output pipe
    server.status = "Stopped"

    if server.name == "bot":
        bot_ready = 0
        launch_bot()
        # Set up the timestamp
        # YYYY-MM-DD HH:MM:SS
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            output = os.fdopen(os.dup(server.input), "a")
            output.write("emergency$%{}\n".format(timestamp))
        except IOError as e:
            if e.errno == errno.EPIPE:
                print("The bot crashed and was unable to be restarted.", file=sys.stderr)
                clean_exit(1)
                return
    else:
        send_threaded_chat("bot", "crashreport${}".format(server.name))
        currently_running = currently_running - 1
        if currently_running == 0:
            # Exit with error
            clean_exit(1)
    server.mutex.release()


# void * heartbeat()
# Uses global `server_list` to know who to send messages to
def heartbeat():
    while True:
        send_threaded_chat("bot", "heartbeat$")
        for _, server in server_list.items():
            send_threaded_chat(server, "/silent-command local heartbeat = true\n")
        time.sleep(15)


# int main()
def main():
    global currently_running
    global bot_ready
    # Initial setup of variables
    # need to work out scope for these, do they all need to be global etc?
    # servers = 0
    # thread_list = []
    currently_running = 0
    bot_ready = 0

    # Redirect certain signals to perform other functions
    signal(SIGINT, stop_all_servers)  # Safe shutdown of all servers
    signal(SIGPIPE, SIG_IGN)  # Crash detection

    # Launch the bot
    launch_bot()

    # Create the heartbeat, also for improved crash detection
    heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
    heartbeat_thread.start()

    for line in sys.stdin:
        line = line.strip()
        if "$" not in line:
            print("Failure to receive input", file=sys.stderr)
            clean_exit(1)

        servername, new_input = line.split("$", 1)
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

            os.kill(server.pid, SIGKILL)  # Send SIGKILL to the server, forcing an immediate shutdown

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

    # Exit successfully
    clean_exit()


def clean_exit(error_code=0):
    # Shut down the bot, giving it time to finish whatever action it is doing
    time.sleep(5)
    bot = find_server("bot")
    os.kill(bot.pid, SIGINT)
    os.waitpid(bot.pid, 0)
    if "bot" in thread_list:
        thread_list["bot"].join()
    bot.input.close()  # Close input pipe
    bot.output.close()  # Close output pipe
    exit(error_code)


if __name__ == "__main__":
    main()
