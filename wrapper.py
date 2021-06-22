#!/usr/bin/env python3

# ///////////////////////////////////////////////////////////////////////////////
# // Copyright © 2020 xx network SEZC                                          //
# //                                                                           //
# // Use of this source code is governed by a license that can be found in the //
# // LICENSE file                                                              //
# ///////////////////////////////////////////////////////////////////////////////

# This script wraps the cMix binaries to provide system management

import argparse
import base64
import json
import logging as log
import os
import stat
import subprocess
import sys
import multiprocessing
import time
import uuid
import boto3
from botocore.config import Config
import botocore.exceptions
import tarfile
import shutil
from OpenSSL import crypto
import hashlib


# FUNCTIONS --------------------------------------------------------------------


def start_cw_logger(cloudwatch_log_group, log_file_path, id_path, region, access_key_id, access_key_secret):
    """
    start_cw_logger is a blocking function which starts the thread to log to cloudwatch.
    This requires a blocking function so we can ensure that if a log file is present,
    it is opened before logging resumes.  This prevents lines from being omitted in cloudwatch.

    :param cloudwatch_log_group: log group name for cloudwatch logging
    :param log_file_path: Path to the log file
    :param id_path: path to node's id file
    :param region: AWS region
    :param access_key_id: aws access key
    :param access_key_secret: aws secret key
    :return The newly created logging process
    :rtype multiprocessing.Process
    """
    # If there is already a log file, open it here so we don't lose records
    log_file = None

    # Configure boto retries
    config = Config(
        retries=dict(
            max_attempts=50
        )
    )

    # Setup cloudwatch logs client
    client = boto3.client('logs', region_name=region,
                          aws_access_key_id=access_key_id,
                          aws_secret_access_key=access_key_secret,
                          config=config)

    # Open the log file read-only and pin its current size if it already exists
    if os.path.isfile(log_file_path):
        log_file = open(log_file_path, 'r')
        log_file.seek(0, os.SEEK_END)

    # Start the log backup service
    log.info("Starting logger for {} at {}...".format(log_file_path, cloudwatch_log_group))
    process = multiprocessing.Process(target=cloudwatch_log,
                                      args=(cloudwatch_log_group, log_file_path,
                                            id_path, log_file, client))
    process.start()
    return process


def cloudwatch_log(cloudwatch_log_group, log_file_path, id_path, log_file, client):
    """
    cloudwatch_log is intended to run in a thread.  It will monitor the file at
    log_file_path and send the logs to cloudwatch.  Note: if the node lacks a
    stream, one will be created for it, named by node ID.

    :param client: cloudwatch client for this logging thread
    :param log_file: log file for this logging thread
    :param cloudwatch_log_group: log group name for cloudwatch logging
    :param log_file_path: Path to the log file
    :param id_path: path to node's id file
    """
    global read_node_id
    # Constants
    megabyte = 1048576  # Size of one megabyte in bytes
    max_size = 100 * megabyte  # Maximum log file size before truncation
    push_frequency = 3  # frequency of pushes to cloudwatch, in seconds
    max_send_size = megabyte

    # Event buffer and storage
    event_buffer = ""  # Incomplete data not yet added to log_events for push to cloudwatch
    log_events = []  # Buffer of events from log not yet sent to cloudwatch
    events_size = 0

    log_file, client, log_stream_name, upload_sequence_token, init_err = init(log_file_path, id_path,
                                                                              cloudwatch_log_group, log_file, client)
    if init_err:
        log.error("Failed to init cloudwatch logging for {}: {}".format(cloudwatch_log_group, init_err))
        return

    last_push_time = time.time()
    last_line_time = time.time()
    while True:
        event_buffer, log_events, events_size, last_line_time = process_line(log_file, event_buffer, log_events,
                                                                             events_size, last_line_time)

        # Check if we should send events to cloudwatch
        log_event_size = 26
        is_over_max_size = len(event_buffer.encode(encoding='utf-8')) + log_event_size + events_size > max_send_size
        is_time_to_push = time.time() - last_push_time > push_frequency

        if (is_over_max_size or is_time_to_push) and len(log_events) > 0:
            # Send to cloudwatch, then reset events, size and push time
            upload_sequence_token, ok = send(client, upload_sequence_token,
                                             log_events, log_stream_name, cloudwatch_log_group)
            if ok:
                events_size = 0
                log_events = []
                last_push_time = time.time()

        # Clear the log file if it has exceeded maximum size
        log_size = os.path.getsize(log_file_path)
        log.debug("Current log {} size: {}".format(log_file_path, log_size))
        if log_size > max_size:
            # Close the old log file
            log.info("Log {} has reached maximum size: {}. Clearing...".format(log_file_path, log_size))
            log_file.close()
            # Overwrite the log with an empty file and reopen
            log_file = open(log_file_path, "w+")
            log.info("Log {} has been cleared. New Size: {}".format(
                log_file_path, os.path.getsize(log_file_path)))


def init(log_file_path, id_path, cloudwatch_log_group, log_file, client):
    """
    Initialize client for cloudwatch logging
    :param client: cloudwatch client for this logging thread
    :param log_file_path: path to log output
    :param id_path: path to id file
    :param cloudwatch_log_group: cloudwatch log group name
    :param log_file: log file to read lines from
    :return log_file, client, log_stream_name, upload_sequence_token:
    """
    global read_node_id
    upload_sequence_token = ""

    # If the log file does not already exist, wait for it
    if not log_file:
        while not os.path.isfile(log_file_path):
            time.sleep(1)
        # Open the newly-created log file as read-only
        log_file = open(log_file_path, 'r')

    # Define prefix for log stream - should be ID based on file
    if read_node_id:
        log_prefix = read_node_id
    # Read node ID from the file
    else:
        log.info("Waiting for ID file...")
        while not os.path.exists(id_path):
            time.sleep(1)
        log_prefix = get_node_id(id_path)

    log_name = os.path.basename(log_file_path)  # Name of the log file
    log_stream_name = "{}-{}".format(log_prefix, log_name)  # Stream name should be {ID}-{node/gateway}.log

    try:
        # Determine if stream exists.  If not, make one.
        streams = client.describe_log_streams(logGroupName=cloudwatch_log_group,
                                              logStreamNamePrefix=log_stream_name)['logStreams']

        if len(streams) == 0:
            # Create a log stream on the fly if ours does not exist
            client.create_log_stream(logGroupName=cloudwatch_log_group, logStreamName=log_stream_name)
        else:
            # If our log stream exists, we need to get the sequence token from this call to start sending to it again
            for s in streams:
                if log_stream_name == s['logStreamName'] and 'uploadSequenceToken' in s.keys():
                    upload_sequence_token = s['uploadSequenceToken']

    except Exception as e:
        return None, None, None, None, e

    return log_file, client, log_stream_name, upload_sequence_token, None


def process_line(log_file, event_buffer, log_events, events_size, last_line_time):
    """
    Accepts current buffer and log events from main loop
    Processes one line of input, either adding an event or adding it to the buffer
    New events are marked by a string in log_starters, or are separated by more than 0.5 seconds
    :param log_file: file to read line from
    :param last_line_time: Timestamp when last log line was read
    :param events_size: message size for log events per aws docs
    :param event_buffer: string buffer of concatenated lines that make up a single event
    :param log_events: current array of events
    :return:
    """
    # using these to deliniate the start of an event
    log_starters = ["INFO", "WARN", "DEBUG", "ERROR", "FATAL", "TRACE"]

    # This controls how long we should wait after a line before assuming it's the end of an event
    force_event_time = 1
    maximum_event_size = 260000

    # Get a line and mark the time it's read
    line = log_file.readline()
    line_time = int(round(time.time() * 1000))  # Timestamp for this line

    # Check the potential size, if over max, we should force a new event
    potential_buffer = event_buffer + line
    is_event_too_big = len(potential_buffer.encode(encoding='utf-8')) > maximum_event_size

    if not line:
        # if it's been more than force_event_time since last line, push buffer to events
        is_new_line = time.time() - last_line_time > force_event_time and event_buffer != ""
        time.sleep(0.5)
    else:
        # Reset last line time
        last_line_time = time.time()
        # If a new event is starting, push buffer to events
        is_new_line = line.split(' ')[0] in log_starters and event_buffer != ""

    if is_new_line or is_event_too_big:
        # Push the buffer into events
        size = len(event_buffer.encode(encoding='utf-8'))
        log_events.append({'timestamp': line_time, 'message': event_buffer})
        event_buffer = ""
        events_size += (size + 26)  # Increment buffer size by message len + 26 (per aws documentation)

    if line:
        if len(line.encode(encoding='utf-8')) > maximum_event_size:
            line = line[:maximum_event_size-1]
        # Push line on to the buffer
        event_buffer += line

    return event_buffer, log_events, events_size, last_line_time


def send(client, upload_sequence_token, log_events, log_stream_name, cloudwatch_log_group):
    """
    send is a helper function for cloudwatch_log, used to push a batch of events to the proper stream
    :param log_events: Log events to be sent to cloudwatch
    :param log_stream_name: Name of cloudwatch log stream
    :param cloudwatch_log_group: Name of cloudwatch log group
    :param client: cloudwatch logs client
    :param upload_sequence_token: sequence token for log stream
    :return: new sequence token
    """
    ok = True
    if len(log_events) == 0:
        return upload_sequence_token

    try:
        if upload_sequence_token == "":
            # for the first message in a stream, there is no sequence token
            resp = client.put_log_events(logGroupName=cloudwatch_log_group,
                                         logStreamName=log_stream_name,
                                         logEvents=log_events)
        else:
            resp = client.put_log_events(logGroupName=cloudwatch_log_group,
                                         logStreamName=log_stream_name,
                                         logEvents=log_events,
                                         sequenceToken=upload_sequence_token)
        upload_sequence_token = resp['nextSequenceToken']  # set the next sequence token

        # IF anything was rejected, log as warning
        if 'rejectedLogEventsInfo' in resp.keys():
            log.warning("Some log events were rejected:")
            log.warning(resp['rejectedLogEventsInfo'])

    except client.exceptions.InvalidSequenceTokenException as e:
        ok = False
        log.warning(f"Boto3 invalidSequenceTokenException encountered: {e}")
        upload_sequence_token = e.response['Error']['Message'].split()[-1]
    except botocore.exceptions.ClientError as e:
        ok = False
        log.error("Boto3 client error encountered: %s" % e)
    except Exception as e:
        ok = False
        log.error(e)
    finally:
        # Always return upload sequence token - dropping this causes lots of errors
        return upload_sequence_token, ok


def check_networking():
    """
    check_networking checks for networking settings essential for operation of
    cMix.
    """
    slowcmd = [
        "sudo /bin/bash -c \"echo 0 > /proc/sys/net/ipv4/tcp_slow_start_after_idle\"",
        "sudo /bin/bash -c \'echo \"net.ipv4.tcp_slow_start_after_idle=0\" >> /etc/sysctl.conf\'"
    ]
    networking_good = True
    slowsetting = open('/proc/sys/net/ipv4/tcp_slow_start_after_idle', 'r').read().strip()
    if '0' not in slowsetting:
        log.warning('tcp_slow_start_after_idle should be disabled, run:\n\t{}'.format(
            '\n\t'.join(slowcmd)))
        networking_good = False
    else:
        networking_good = True
    # Alternatively, if the initial windows are 700, that's acceptable
    # too.
    if not networking_good:
        ipsetting = subprocess.run(['ip', 'route', 'show'], stdout=subprocess.PIPE)
        ipsettingout = ipsetting.stdout.decode('utf-8')
        if 'initcwnd 700' in ipsettingout and 'initrwnd 700' in ipsettingout:
            networking_good = True
    return networking_good


def download(src_path, dst_path, s3_bucket, region,
             access_key_id, access_key_secret):
    """
    Downloads file at src_path on s3_bucket to dst_path using
    the provided access_key_id and access_key_secret.

    :param src_path: Path of file on S3 bucket
    :type src_path: str
    :param dst_path: Path of local destination
    :type dst_path: str
    :param s3_bucket: Name of S3 bucket
    :type s3_bucket: str
    :param region: Region of S3 bucket
    :type region: str
    :param access_key_id: Access key ID for bucket access
    :type access_key_id: str
    :param access_key_secret: Access key secret for bucket access
    :type access_key_secret: str
    :return: None
    :rtype: None
    """
    try:
        s3 = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=access_key_secret,
            region_name=region).resource("s3")
        s3.Bucket(s3_bucket).download_file(src_path, dst_path)
        log.debug("Successfully downloaded to {} from {}/{}".format(dst_path,
                                                                    s3_bucket,
                                                                    src_path))
    except Exception as error:
        log.error("Unable to download {} from {}: {}".format(src_path, s3_bucket, error),
                  exc_info=True)


def start_binary(bin_path, log_file_path, bin_args):
    """
    Starts the binary at the given path with the given args.
    Returns the newly-created subprocess.

    :param bin_path: Path to the binary
    :type bin_path: str
    :param log_file_path: Path to the binary log file
    :type log_file_path: str
    :param bin_args: Arguments for the binary
    :type bin_args: list[str]
    :return: Newly-created subprocess
    :rtype: subprocess.Popen
    """
    with open(log_file_path, "a") as err_out:
        p = subprocess.Popen([bin_path] + bin_args,
                             stdout=subprocess.DEVNULL,
                             stderr=err_out)
        log.info(bin_path + " started at PID " + str(p.pid))
        return p


def terminate_process(p):
    """
    Terminates the given subprocess.

    :param p: Process to terminate
    :type p: subprocess.Popen
    """
    if p is not None and p.poll() is None:
        pid = p.pid
        log.info("Terminating process {}...".format(pid))
        p.terminate()
        log.info("Process {} terminated with exit code {}".
                 format(pid, p.wait()))


def terminate_multiprocess(p):
    """
    Terminates the given multiprocess.

    :param p: Process to terminate
    :type p: multiprocessing.Process
    """
    if p is not None and p.is_alive():
        pid = p.pid
        log.info("Terminating process {}...".format(pid))
        p.terminate()
        while p.is_alive():
            log.info("Waiting for {} to terminate...".format(pid))
            time.sleep(0.5)
        log.info("Process {} terminated with exit code {}".
                 format(pid, p.exitcode))


# generated_uuid is a static cached UUID used as the node_id
generated_uuid = None
# read_node_id is a static cached node id when we successfully read it
read_node_id = None


def get_node_id(id_path):
    """
    Obtain the ID of the running node.

    :param id_path: the path to the node id
    :type id_path: str
    :return: The node id OR a UUID by host and time if node id file absent
    :rtype: str
    """
    global generated_uuid, read_node_id
    # if we've already read it successfully from the file, return it
    if read_node_id:
        return read_node_id
    # Read it from the file
    try:
        if os.path.exists(id_path):
            with open(id_path, 'r') as id_file:
                new_node_id = json.loads(id_file.read().strip()).get("id", None)
                if new_node_id:
                    read_node_id = new_node_id
                    return new_node_id
    except Exception as error:
        log.warning("Could not open node ID at {}: {}".format(id_path, error))

    # If that fails, then generate, or use the last generated UUID
    if not generated_uuid:
        generated_uuid = str(uuid.uuid1())
        log.warning("Generating random instance ID: {}".format(generated_uuid))
    return generated_uuid


def verify_cmd(in_buf, public_key_path):
    """
    verify_cmd checks the command signature against the network certificate.

    :param in_buf: the command file buffer
    :type in_buf: file object
    :param public_key_path: The path to the network public key certificate
    :type public_key_path: str
    :return: The json dict for the command, and if the signature worked or not
    :rtype: dict, bool
    """

    with open(public_key_path, 'r') as file:
        command_json = None
        try:
            key = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
            cmd = in_buf.readline().strip()
            command_json = json.loads(cmd)
            sig_json = json.loads(in_buf.readline())
            signature = base64.b64decode(sig_json.get('signature'))
            crypto.verify(key, signature, bytes(cmd, 'utf-8'), 'sha256')
            return command_json, True
        except Exception as error:
            log.error("Unable to verify command: {}".format(error))
            return command_json, False


def save_cmd(file_path, dest_dir, valid, cmd_time):
    """
    save_cmd saves the command json files to a log directory

    :param file_path: The source path of the command to save
    :type file_path: str
    :param dest_dir: the destination directory
    :type dest_dir: str
    :param valid: is this a valid command file
    :type valid: bool
    :param cmd_time: the timestamp of the command
    :type cmd_time: timestamp
    :return: Nothing
    :rtype: None
    """
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    fparts = os.path.basename(file_path).split('.')
    if not valid:
        fparts[0] = "INVALID_{}".format(fparts[0])
    # destdir/command_2849204.json
    dest = "{}/{}_{}.{}".format(dest_dir, fparts[0], int(cmd_time), fparts[1])
    shutil.copyfile(file_path, dest)


def get_args():
    """
    get_args handles argument parsing for the script
    :return arguments in dict format:
    """
    parser = argparse.ArgumentParser()

    # Management arguments
    parser.add_argument("--s3-path", type=str, required=True,
                        help="S3 management directory")
    parser.add_argument("--s3-management-bucket", type=str, required=True,
                        help="S3 management bucket name")
    parser.add_argument("--s3-bin-bucket", type=str, required=True,
                        help="S3 bins bucket name")
    parser.add_argument("--s3-access-key", type=str, required=True,
                        help="S3 access key")
    parser.add_argument("--s3-secret", type=str, required=True,
                        help="S3 access key secret")
    parser.add_argument("--s3-region", type=str, required=True,
                        help="S3 region")

    # Wrapper arguments
    parser.add_argument("--disable-consensus", action="store_true", required=False,
                        help="Disable Consensus integration (For test environments only)",
                        default=False)
    parser.add_argument("--disable-cloudwatch", action="store_true", required=False,
                        help="Disable uploading log events to CloudWatch",
                        default=False)
    parser.add_argument("--management-cert", type=str, required=False,
                        help="Path of the management certificate file",
                        default="/opts/xxnetwork/creds/network_management.crt")
    parser.add_argument("--tmp-dir", type=str, required=False,
                        help="Directory for placing temporary files",
                        default="/tmp")
    parser.add_argument("--cmd-dir", type=str, required=False,
                        help="Directory used for saving command file history",
                        default="/opt/xxnetwork/logs/cmdlog")
    parser.add_argument("--wrapper-log", type=str, required=False,
                        help="Path of the wrapper log file",
                        default="/opt/xxnetwork/logs/wrapper.log")

    # Elixxir arguments
    parser.add_argument("--binary", type=str, required=True,
                        help="Path of the Elixxir binary")
    parser.add_argument("--config-path", type=str, required=True,
                        help="Path of the Elixxir config file")
    parser.add_argument("--log-path", type=str, required=False,
                        default="/opt/xxnetwork/logs/xx.log",
                        help="Path of the Elixxir log file")
    parser.add_argument("--gpu-lib", type=str, required=False,
                        default="/opt/xxnetwork/lib/libpowmosm75.so",
                        help="Path of the GPU exponentiation library")
    parser.add_argument("--gpu-bin", type=str, required=False,
                        default="/opt/xxnetwork/lib/libpow.fatbin",
                        help="Path of the GPU bin file")
    parser.add_argument("--id-path", type=str, required=False,
                        default="/opt/xxnetwork/logs/IDF.json",
                        help="Path of the Elixxir ID file")
    parser.add_argument("--err-path", type=str, required=False,
                        help="Path of the Elixxir error recovery file",
                        default="/opt/xxnetwork/node-logs/node-err.log")
    parser.add_argument("--cloudwatch-log-group", type=str, required=False,
                        help="Log group for CloudWatch logging",
                        default="xxnetwork-logs-prod")

    # Consensus arguments
    parser.add_argument("--consensus-binary", type=str, required=False,
                        help="Path of the Consensus binary",
                        default="/opt/xxnetwork/bin/xxnetwork-consensus")
    parser.add_argument("--consensus-log", type=str, required=False,
                        help="Path of the Consensus log file",
                        default="/opt/xxnetwork/logs/consensus.log")
    parser.add_argument("--consensus-cw-group", type=str, required=False,
                        help="Log group for Consensus CloudWatch logging",
                        default="xxnetwork-consensus-prod")

    args, unknown = parser.parse_known_args()

    # Handle unknown args
    if len(unknown) > 0:
        log.warning("Unknown arguments: {}".format(unknown))
    return vars(args)


# TARGET CLASS -----------------------------------------------------------------
# Define possible local targets for commands

class Targets:
    BINARY = 'binary'
    GPULIB = 'gpulib'
    GPUBIN = 'gpubin'
    WRAPPER = 'wrapper'
    CERT = 'cert'
    CONSENSUS_BINARY = 'consensus_binary'
    LOGGER = 'logger'


# MAIN FUNCTION ---------------------------------------------------------------


def main():
    # Configure logger
    log.basicConfig(format='[%(levelname)s] %(asctime)s: %(message)s',
                    level=log.INFO, datefmt='%d-%b-%y %H:%M:%S')

    # Command line arguments
    args = get_args()
    log.info("Running with configuration: {}".format(args))
    binary_path = args["binary"]
    gpulib_path = args["gpu_lib"]
    gpubin_path = args["gpu_bin"]
    management_directory = args["s3_path"]
    rsa_certificate_path = args["management_cert"]
    s3_management_bucket_name = args["s3_bucket"]
    s3_access_key_id = args["s3_access_key"]
    s3_access_key_secret = args["s3_secret"]
    s3_bucket_region = args["s3_region"]
    log_path = args["log_path"]
    err_output_path = args["err_path"]
    version_file = management_directory + "/version.jsonl"
    command_file = management_directory + "/command.jsonl"
    tmp_dir = args["tmp_dir"]
    os.makedirs(tmp_dir, exist_ok=True)
    cmd_log_dir = args["cmd_dir"]
    consensus_log = args["consensus_log"]
    consensus_grp = args["consensus_cw_group"]
    consensus_config = args["consensus_config"]
    config_file = args["config_path"]

    # The valid "install" paths we can write to, with their local paths for
    # this machine
    valid_paths = {
        Targets.BINARY: os.path.abspath(os.path.expanduser(binary_path)),
        Targets.GPULIB: os.path.abspath(os.path.expanduser(gpulib_path)),
        Targets.GPUBIN: os.path.abspath(os.path.expanduser(gpubin_path)),
        Targets.WRAPPER: os.path.abspath(sys.argv[0]),
        Targets.CERT: rsa_certificate_path,
        Targets.CONSENSUS_BINARY: args["consensus_binary"],
    }

    # Record the most recent command timestamp
    # to avoid executing duplicate commands
    timestamps = [0, time.time()]
    # Record the most recent error timestamp to avoid restart loops
    last_error_timestamp = 0

    # Globally keep track of the main process being wrapped
    process = None
    # Globally keep track of the consensus process
    consensus_process = None
    # Globally keep track of the logging process
    logging_process = None
    # Globally keep track of the consensus logging process
    consensus_logging_process = None

    # CONTROL FLOW -----------------------------------------------------------------

    # Start the log backup service
    if not args["disable_cloudwatch"]:
        logging_process = start_cw_logger(args["cloudwatch_log_group"], log_path,
                                          args["idpath"], s3_bucket_region,
                                          s3_access_key_id, s3_access_key_secret)
        if not args["disable_consensus"] and management_directory == "server":
            consensus_logging_process = start_cw_logger(consensus_grp, consensus_log,
                                                        args["idpath"], s3_bucket_region,
                                                        s3_access_key_id, s3_access_key_secret)

    # Frequency (in seconds) of checking for new commands
    command_frequency = 10
    log.info("Script initialized at {}".format(time.time()))
    # Main command/control loop
    remotes_paths = [version_file, command_file]
    while True:
        time.sleep(command_frequency)

        # If there is a (recently modified) recovered error file present, restart the main process
        if err_output_path \
                and os.path.isfile(err_output_path) \
                and os.path.getmtime(err_output_path) > last_error_timestamp:
            log.warning("Restarting binary due to error...")
            time.sleep(10)
            try:
                # Terminate the process if it still exists
                if not (process is None or process.poll() is not None):
                    terminate_process(process)

                # Restart the main process
                process = start_binary(valid_paths[Targets.BINARY], log_path,
                                       ["--config", config_file])
            except IOError as err:
                log.error(err)
            last_error_timestamp = time.time()

        for i, remote_path in enumerate(remotes_paths):
            try:
                # Obtain the latest command file
                local_path = "{}/{}".format(tmp_dir, os.path.basename(remote_path))
                download(remote_path, local_path,
                         s3_management_bucket_name, s3_bucket_region,
                         s3_access_key_id, s3_access_key_secret)

                # Load the command file into JSON
                with open(local_path, 'r') as cmd_file:

                    # Verify the command file signature
                    signed_commands, ok = verify_cmd(cmd_file, rsa_certificate_path)
                    if signed_commands is None:
                        log.error("Empty command file: {}".format(local_path))
                        save_cmd(local_path, cmd_log_dir, False, time.time())
                        continue

                    # Handle invalid signature
                    if not ok:
                        log.error("Failed to verify signature for {}!".format(
                            local_path), exc_info=True)
                        save_cmd(local_path, cmd_log_dir, ok, time.time())
                        continue

                # Save the command into a log
                timestamp = signed_commands.get("timestamp", 0)
                save_cmd(local_path, cmd_log_dir, ok, timestamp)

                # If the commands occurred before the script, skip
                # Note: We do not update unless we get a command we
                # have verified and can actually attempt to run.
                if timestamp <= timestamps[i]:
                    log.debug("Command set with timestamp {} is outdated, "
                              "ignoring...".format(timestamp))
                    continue

                # Note: We get the UUID for every valid command in case it changes
                node_id = get_node_id(args["idpath"])

                # Execute the commands in sequence
                for command in signed_commands.get("commands", list()):

                    # If the command does not apply to us, note that and move on
                    if "nodes" in command:
                        node_targets = command.get("nodes", list())
                        if node_targets and node_id not in node_targets:
                            log.info("Command does not apply to {}".format(node_id))
                            timestamps[i] = timestamp
                            continue

                    # Command applies, so obtain command information
                    command_type = command.get("command", "")
                    target = command.get("target", "")
                    info = command.get("info", dict())
                    log.info("Executing command: {}".format(command))

                    # START COMMAND ===========================
                    if command_type == "start":

                        # Ensure network settings are properly configured before allowing a start
                        if not check_networking():
                            log.error("Unacceptable network settings, refusing to start. "
                                      "Run the suggested commands")
                            timestamps[i] = timestamp
                            continue

                        # Decide which type of binary to start
                        if target == Targets.BINARY and (process is None or process.poll() is not None):
                            process = start_binary(valid_paths[Targets.BINARY], log_path,
                                                   ["--config", config_file])
                        elif not args["disable_consensus"] and target == Targets.CONSENSUS_BINARY and \
                                (consensus_process is None or consensus_process.poll() is not None):
                            consensus_process = start_binary(valid_paths[Targets.CONSENSUS_BINARY], consensus_log,
                                                             ["--config", consensus_config,
                                                              "--cmixconfig", config_file])
                        elif target == Targets.LOGGER:
                            if not args["disable_cloudwatch"] \
                                    and (logging_process is None or not logging_process.is_alive()):
                                logging_process = start_cw_logger(args["cloudwatch_log_group"], log_path,
                                                                  args["idpath"], s3_bucket_region,
                                                                  s3_access_key_id, s3_access_key_secret)
                            if not args["disable_consensus"] and management_directory == "server" \
                                    and (consensus_logging_process is None or not consensus_logging_process.is_alive()):
                                consensus_logging_process = start_cw_logger(consensus_grp, consensus_log,
                                                                            args["idpath"], s3_bucket_region,
                                                                            s3_access_key_id, s3_access_key_secret)

                    # STOP COMMAND ===========================
                    elif command_type == "stop":
                        # Stop the wrapped process
                        if target == Targets.BINARY:
                            terminate_process(process)
                        elif target == Targets.CONSENSUS_BINARY:
                            terminate_process(consensus_process)
                        elif target == Targets.LOGGER:
                            terminate_multiprocess(logging_process)
                            terminate_multiprocess(consensus_logging_process)

                    # DELAY COMMAND ===========================
                    elif command_type == "delay":
                        # Delay for the given amount of time
                        # NOTE: Provided in MS, converted to seconds
                        duration = info.get("time", 0)
                        log.info("Delaying for {}ms...".format(duration))
                        time.sleep(duration / 1000)

                    # UPDATE COMMAND ===========================
                    elif command_type == "update":

                        # Handle disabled updates flag
                        if args["disableupdates"]:
                            log.error("Update command ignored, updates disabled!")
                            timestamps[i] = timestamp
                            continue

                        # Handle disabled consensus flag
                        if (target == Targets.CONSENSUS_BINARY or target == Targets.CONSENSUS_STATE) \
                                and args["disable_consensus"]:
                            log.error("Update command ignored, consensus disabled!")
                            timestamps[i] = timestamp
                            continue

                        # Verify valid install path
                        if target not in valid_paths.keys():
                            log.error("Invalid update target: {}. Expected one of: {}".format(
                                target, valid_paths.values()))
                            timestamps[i] = timestamp
                            continue

                        # Get local destination path
                        install_path = valid_paths[target]
                        # Get remote source path
                        update_path = "{}/{}".format(management_directory, info.get("path", ""))
                        log.info("Downloading file at {} to {}...".format(update_path, install_path))

                        # Make directories and download file to temporary location
                        os.makedirs(os.path.dirname(install_path), exist_ok=True)
                        tmp_path = install_path + ".tmp"
                        download(update_path, tmp_path,
                                 s3_management_bucket_name, s3_bucket_region,
                                 s3_access_key_id, s3_access_key_secret)

                        # Ensure the hash of the downloaded file matches the hash in the command
                        update_bytes = bytes(open(tmp_path, 'rb').read())
                        actual_hash = hashlib.sha256(update_bytes).hexdigest()
                        expected_hash = info.get("sha256sum", "")
                        if actual_hash != expected_hash:
                            os.remove(path=tmp_path)
                            log.error("Downloaded file {} does not match provided hash. Expected {}, got {}".format(
                                tmp_path, expected_hash, actual_hash))
                            timestamps[i] = timestamp
                            continue

                        # Move the downloaded file into place, overwriting anything that's there
                        try:
                            os.replace(tmp_path, install_path)
                        except Exception as err:
                            log.error("Could not overwrite {} with {}: {}".format(
                                install_path, tmp_path, err))
                            timestamps[i] = timestamp
                            continue

                        # Handle binary updates
                        if target == Targets.BINARY or target == Targets.CONSENSUS_BINARY:
                            os.chmod(install_path, stat.S_IEXEC)

                        # Handle GPU library updates
                        if target == Targets.GPULIB or target == Targets.GPUBIN:
                            os.chmod(install_path, stat.S_IREAD)

                        # Handle consensus state updates
                        if target == Targets.CONSENSUS_STATE:
                            os.chmod(install_path, stat.S_IREAD)

                            # Assemble the path to extract the new consensus directory
                            extract_path = os.path.dirname(install_path)
                            # Assemble the path to the extracted consensus directory
                            dest_path = os.path.join(extract_path, 'consensus')

                            # Remove existing state directory
                            try:
                                shutil.rmtree(dest_path)
                            except OSError as e:
                                log.error("Unable to remove {}: {}".format(dest_path, e))

                            # Extract the tarball
                            with tarfile.open(install_path) as tarball:
                                tarball.extractall(path=extract_path)

                        # Handle wrapper updates
                        if target == Targets.WRAPPER:
                            os.chmod(install_path, stat.S_IEXEC | stat.S_IREAD)
                            log.info("Wrapper script updated, exiting now...")
                            os._exit(0)

                    log.info("Completed command: {}".format(command))

                # Update the timestamp in order to avoid repetition
                timestamps[i] = timestamp
            except Exception as err:
                log.error("Unable to execute commands: {}".format(err),
                          exc_info=True)


if __name__ == "__main__":
    main()
