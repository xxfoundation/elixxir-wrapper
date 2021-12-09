#!/usr/bin/env python3

# ///////////////////////////////////////////////////////////////////////////////
# // Copyright © 2020 xx network SEZC                                          //
# //                                                                           //
# // Use of this source code is governed by a license that can be found in the //
# // LICENSE file                                                              //
# ///////////////////////////////////////////////////////////////////////////////

# This script wraps xx network binaries to provide system management
# via command files, binary updates via blockchain, as well as network logging

import argparse
import base64
import json
import logging as log
import os
import random
import stat
import subprocess
import sys
import multiprocessing
import time
import boto3
from botocore.config import Config
import shutil
from OpenSSL import crypto
from substrateinterface import SubstrateInterface
import hashlib

########################################################################################################################
# Blockchain Updates
########################################################################################################################


def get_substrate_provider(consensus_url):
    """
    Get Substrate Provider to Listening on websocket of the Substrate Node configured with network registry json file

    :param consensus_url: listening address:port of the substrate server
    :return: Substrate Network Provider used to query blockchain
    """
    try:
        return SubstrateInterface(url=consensus_url)
    except ConnectionRefusedError:
        log.error("No local Substrate node running.")
        return None
    except Exception as e:
        log.error(f"Failed to get substrate chain connection: {e}")
        return None


def check_sync(substrate):
    """
    Polls Substrate Chain to determine whether the Node is synced

    :param substrate: The active substrate connection
    :return: True if Node is synced, else False
    """
    try:
        result = substrate.rpc_request('system_syncState', []).get('result')
        return result["currentBlock"] == result["highestBlock"]
    except Exception as e:
        log.error(f"Failed to query sync state: {e}")
    return False


def poll_cmix_hashes(substrate):
    """
    Polls Substrate Chain information to feed cmix with the current cmix hashes

    :param substrate: The active substrate connection
    :return: dictionary with cmix hashes, empty dict if not synced, or None if an Exception occurred
    """
    # Check if node is fully synced
    if check_sync(substrate) is False:
        return dict()

    try:
        cmix_hashes = substrate.query(
            module='XXCmix',
            storage_function='CmixHashes',
            params=[]
        )
        result = cmix_hashes.value
        log.debug(f"cMix hashes: {result}")
        return result
    except Exception as e:
        log.error(f"Connection lost while in \'substrate.query(\"XXCmix\", \"CmixHashes\")\'. Error: {e}")
        return None


def poll_ready(substrate):
    """
    Polls Substrate Chain information to feed cmix with the node's state

    :param substrate: The active substrate connection
    :return: True if node is ready, else false
    """
    try:
        validator_set = substrate.query("Session", "Validators")
    except Exception as e:
        log.error(f"Connection lost while in \'substrate.query(\"Session\", \"Validators\")\'. Error: {e}")
        return

    try:
        disabled_set = substrate.query("Session", "DisabledValidators")
    except Exception as e:
        log.error(f"Connection lost while in \'substrate.query(\"Session\", \"DisabledValidators\")\'. Error: {e}" )
        return

    # Bc we use pop to remove disabled, go backwards through this list. Otherwise, popping early index shifts later ones
    disabled_set.value.reverse()
    for val in disabled_set.value:
        validator_set.value.pop(val)

    found = False
    for val in validator_set.value:
        try:
            data = substrate.query("Staking", "Bonded", [val])
        except Exception as e:
            log.error(f"Failed to query Staking Bonded {val}: {e}")
            return
        controller = data.value

        try:
            data = substrate.query("Staking", "Ledger", [controller])
        except Exception as e:
            log.error(f"Failed to query Staking Ledger {controller}: {e}")
            return
        ledger = data.value

        cmix_root = ledger['cmix_id']
        if cmix_root == hex_id:
            log.debug(f"Node found in active validator set: {val}")
            found = True
            break
        if found is False:
            log.debug("Node not in validator set for current era, waiting...")
    return found


########################################################################################################################
# Logging
########################################################################################################################


def start_cw_logger(cloudwatch_log_group, log_file_path, id_path, region, access_key_id, access_key_secret):
    """
    start_cw_logger is a blocking function which starts the thread to log to cloudwatch.
    This requires a blocking function so we can ensure that if a log file is present,
    it is opened before logging resumes. This prevents lines from being omitted in cloudwatch.

    :param cloudwatch_log_group: log group name
    :param log_file_path: Path to the log file
    :param id_path: path to node's id file
    :param region: AWS region
    :param access_key_id: aws access key
    :param access_key_secret: aws secret key
    :return The newly created logging process
    :rtype multiprocessing.Process
    """
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

    # Start the log backup service
    log.info(f"Starting logger for {log_file_path} at {cloudwatch_log_group}...")
    process = multiprocessing.Process(target=cloudwatch_log,
                                      args=(cloudwatch_log_group, log_file_path,
                                            id_path, client))
    process.start()
    return process


def cloudwatch_log(cloudwatch_log_group, log_file_path, id_path, client):
    """
    cloudwatch_log is intended to run in a thread.  It will monitor the file at
    log_file_path and send the logs to cloudwatch. Note: if the node lacks a
    stream, one will be created for it, named by node ID.

    :param client: cloudwatch client for this logging thread
    :param cloudwatch_log_group: log group name
    :param log_file_path: Path to the log file
    :param id_path: path to node's id file
    """

    while True:
        try:
            log_stream_name, upload_sequence_token = init(log_file_path, id_path,
                                                          cloudwatch_log_group, client)
            log_loop(log_file_path, cloudwatch_log_group, client, log_stream_name, upload_sequence_token)
        except Exception as e:
            log.error(f"Unhandled logging error: {e}", exc_info=True)
            continue


def init(log_file_path, id_path, cloudwatch_log_group, client):
    """
    Initialize the logging client and associated parameters

    :param client: cloudwatch client for this logging thread
    :param log_file_path: Path to the log file
    :param id_path: path to id file
    :param cloudwatch_log_group: log group name
    :return log_stream_name, upload_sequence_token:
    """
    # Wait for the IDF in order to use ID as log prefix
    log.info("Waiting for IDF...")
    while read_cmix_id(id_path) is None:
        time.sleep(10)
    log_prefix = read_cmix_id(id_path)

    log_name = os.path.basename(log_file_path)  # Name of the log file
    log_stream_name = f"{log_prefix}-{log_name}"  # Stream name should be {ID}-{node/gateway/wrapper}.log

    # Determine if stream exists.  If not, make one.
    streams = client.describe_log_streams(logGroupName=cloudwatch_log_group,
                                          logStreamNamePrefix=log_stream_name)['logStreams']

    upload_sequence_token = ""
    if len(streams) == 0:
        # Create a log stream on the fly if ours does not exist
        client.create_log_stream(logGroupName=cloudwatch_log_group, logStreamName=log_stream_name)
    else:
        # If our log stream exists, we need to get the sequence token from this call to start sending to it again
        for s in streams:
            if log_stream_name == s['logStreamName'] and 'uploadSequenceToken' in s.keys():
                upload_sequence_token = s['uploadSequenceToken']

    return log_stream_name, upload_sequence_token


def log_loop(log_file_path, cloudwatch_log_group, client, log_stream_name, upload_sequence_token):
    """
    Handles the main loop for cloudwatch logging, including log file truncation

    :param log_file_path: Path to the log file
    :param cloudwatch_log_group: log group name
    :param client: Boto3 client for this logging thread
    :param log_stream_name: log stream name
    :param upload_sequence_token: sequence token for log stream start
    :return: None
    """
    # Constants
    megabyte = 1048576  # Size of one megabyte in bytes
    max_size = 100 * megabyte  # Maximum log file size before truncation
    push_frequency = 30  # frequency of pushes to cloudwatch, in seconds
    jitter_size = 1000  # Variable time (in ms) for log push jitter
    jitter_frequency = push_frequency + (random.randint(-jitter_size, jitter_size) / 1000)
    max_send_size = megabyte
    max_events = 10000

    # Event buffer and storage
    event_buffer = ""  # Incomplete data not yet added to log_events for push to cloudwatch
    log_events = []  # Buffer of events from log not yet sent to cloudwatch
    events_size = 0

    # Wait for the log file to exist, then open it
    log.info(f"Waiting for {log_file_path}...")
    while not os.path.isfile(log_file_path):
        time.sleep(1)
    # Open the newly-created log file as read-only
    log_file = open(log_file_path, 'r')
    log_file.seek(0, os.SEEK_END)

    last_push_time = time.time()
    last_line_time = time.time()
    while True:
        event_buffer, log_events, events_size, last_line_time = process_line(log_file, event_buffer, log_events,
                                                                             events_size, last_line_time)

        # Check if we should send events to cloudwatch
        log_event_size = 26
        is_over_max_size = len(event_buffer.encode(encoding='utf-8')) + log_event_size + events_size > max_send_size
        is_over_max_events = len(log_events) >= max_events
        is_time_to_push = time.time() - last_push_time > jitter_frequency

        if (is_over_max_size or is_over_max_events or is_time_to_push) and len(log_events) > 0:
            jitter_frequency = push_frequency + (random.randint(-jitter_size, jitter_size) / 1000)
            # Send to cloudwatch, then reset events, size and push time
            upload_sequence_token = send(client, upload_sequence_token,
                                         log_events, log_stream_name, cloudwatch_log_group)
            events_size = 0
            log_events = []
            last_push_time = time.time()

        # Clear the log file if it has exceeded maximum size
        log_size = os.path.getsize(log_file_path)
        log.debug(f"Current log {log_file_path} size: {log_size}")
        if log_size > max_size:
            # Close the old log file
            log.info(f"Log {log_file_path} has reached maximum size: {log_size}. Clearing...")
            log_file.close()
            # Overwrite the log with an empty file and reopen
            log_file = open(log_file_path, "w+")
            log.info(f"Log {log_file_path} has been cleared. New Size: {os.path.getsize(log_file_path)}")


def process_line(log_file, event_buffer, log_events, events_size, last_line_time):
    """
    Accepts current buffer and log events from log_loop
    Processes one line of input, either adding an event or adding it to the buffer
    New events are marked by a string in log_starters, or are separated by more than 0.5 seconds

    :param log_file: file to read line from
    :param last_line_time: Timestamp when last log line was read
    :param events_size: message size for log events per aws docs
    :param event_buffer: string buffer of concatenated lines that make up a single event
    :param log_events: current array of events
    :return event_buffer, log_events, events_size, last_line_time:
    """
    # using these to delineate the start of an event
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
            line = line[:maximum_event_size - 1]
        # Push line on to the buffer
        event_buffer += line

    return event_buffer, log_events, events_size, last_line_time


def send(client, upload_sequence_token, log_events, log_stream_name, cloudwatch_log_group):
    """
    Helper function for log_loop, used to push a batch of events to the proper stream

    :param log_events: Log events to be sent to cloudwatch
    :param log_stream_name: log stream name
    :param cloudwatch_log_group: Name of cloudwatch log group
    :param client: Boto3 client for this logging thread
    :param upload_sequence_token: sequence token for log stream
    :return: new sequence token
    """
    if len(log_events) == 0:
        return upload_sequence_token

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

    return upload_sequence_token


########################################################################################################################
# Command Functions
########################################################################################################################


def check_networking():
    """
    check_networking checks for networking settings essential for operation of cMix.
    """
    slowcmd = [
        "sudo /bin/bash -c \"echo 0 > /proc/sys/net/ipv4/tcp_slow_start_after_idle\"",
        "sudo /bin/bash -c \'echo \"net.ipv4.tcp_slow_start_after_idle=0\" >> /etc/sysctl.conf\'"
    ]
    networking_good = True
    slowsetting = open('/proc/sys/net/ipv4/tcp_slow_start_after_idle', 'r').read().strip()
    if '0' not in slowsetting:
        log.warning('tcp_slow_start_after_idle should be disabled, run:\n\t{}'.format('\n\t'.join(slowcmd)))
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
        log.debug(f"Successfully downloaded to {dst_path} from {s3_bucket}/{src_path}")
    except Exception as error:
        log.error(f"Unable to download {src_path} from {s3_bucket}: {error}", exc_info=True)


def update(target, tmp_path, install_path, expected_hash):
    """
    Update the current file with a staged file, assuming hashes match

    :param target: Update type as defined by Targets class
    :param tmp_path: Staged update file
    :param install_path: Path to update the staged file over
    :param expected_hash: Hash that is expected to match the staged file
    :return: True if update successful, else false
    """
    # Ensure the hash of the downloaded file matches the hash in the command
    update_bytes = bytes(open(tmp_path, 'rb').read())
    actual_hash = hashlib.blake2s(update_bytes).hexdigest()
    if actual_hash != expected_hash:
        os.remove(path=tmp_path)
        log.error(f"Downloaded file {tmp_path} does not match provided hash. Expected {expected_hash}, got {actual_hash}")
        return False

    # Move the downloaded file into place, overwriting anything that's there
    try:
        os.makedirs(os.path.dirname(install_path), exist_ok=True)
        os.replace(tmp_path, install_path)
    except Exception as err:
        log.error(f"Could not overwrite {install_path} with {tmp_path}: {err}")
        return False

    # Handle binary updates
    if target == Targets.BINARY:
        os.chmod(install_path, stat.S_IEXEC)

    # Handle GPU library updates
    if target == Targets.GPULIB or target == Targets.GPUBIN:
        os.chmod(install_path, stat.S_IREAD)

    # Handle wrapper updates
    if target == Targets.WRAPPER:
        os.chmod(install_path, stat.S_IEXEC | stat.S_IREAD)
        log.info("Wrapper script updated, exiting now...")
        os._exit(0)

    # Return successfully
    return True


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
        log.info(f"{bin_path} started at PID {p.pid}")
        return p


def terminate_process(p):
    """
    Terminates the given subprocess.

    :param p: Process to terminate
    :type p: subprocess.Popen
    """
    if p is not None and p.poll() is None:
        pid = p.pid
        log.info(f"Terminating process {pid}...")
        p.terminate()
        log.info(f"Process {pid} terminated with exit code {p.wait()}")


def terminate_multiprocess(p):
    """
    Terminates the given multiprocess.

    :param p: Process to terminate
    :type p: multiprocessing.Process
    """
    if p is not None and p.is_alive():
        pid = p.pid
        log.info(f"Terminating process {pid}...")
        p.terminate()
        while p.is_alive():
            log.info(f"Waiting for {pid} to terminate...")
            time.sleep(0.5)
        log.info(f"Process {pid} terminated with exit code {p.exitcode}")


# Static cached cmix ID when we successfully read it from the IDF
cmix_id = None
# Hex version of the cmix_id passed to the blockchain
hex_id = None


def read_cmix_id(id_path):
    """
    Obtain the ID of the running node/gateway.

    :param id_path: the path to the IDF
    :type id_path: str
    :return: The ID from the IDF
    :rtype: str
    """
    global cmix_id, hex_id
    # if we've already read it successfully from the file, return it
    if cmix_id:
        return cmix_id
    # Read it from the file
    try:
        if os.path.exists(id_path):
            with open(id_path, 'r') as id_file:
                id_json = json.loads(id_file.read().strip())
                new_cmix_id = id_json.get("id", None)
                new_hex_id = id_json.get("hexNodeID", None)
                if new_hex_id:
                    hex_id = new_hex_id
                if new_cmix_id:
                    cmix_id = new_cmix_id
                    return cmix_id
    except Exception as error:
        log.warning(f"Could not open IDF at {id_path}: {error}")
        return None


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
            log.error(f"Unable to verify command: {error}")
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
        fparts[0] = f"INVALID-{fparts[0]}"
    # destdir/command-2849204.json
    dest = f"{dest_dir}/{fparts[0]}-{int(cmd_time)}.{fparts[1]}"
    shutil.copyfile(file_path, dest)


########################################################################################################################
# Control Flow
########################################################################################################################

def get_args():
    """
    get_args handles argument parsing for the script
    :return arguments in dict format:
    """
    parser = argparse.ArgumentParser()

    # Management arguments
    parser.add_argument("--s3-access-key", type=str, required=True,
                        help="S3 access key")
    parser.add_argument("--s3-secret", type=str, required=True,
                        help="S3 access key secret")
    parser.add_argument("--s3-management-bucket", type=str, required=False,
                        help="S3 management bucket name",
                        default="elixxir-management-mainnet")
    parser.add_argument("--s3-bin-bucket", type=str, required=False,
                        help="S3 binary bucket name",
                        default="elixxir-bins")
    parser.add_argument("--s3-region", type=str, required=False,
                        help="S3 region",
                        default="us-west-1")

    # Wrapper arguments
    parser.add_argument("--verbose", action='store_true', required=False,
                        help="Print debug information",
                        default=False)
    parser.add_argument("--gateway", action="store_true", required=False,
                        help="Enable gateway mode",
                        default=False)
    parser.add_argument("--disable-cloudwatch", action="store_true", required=False,
                        help="Disable uploading log events to CloudWatch",
                        default=False)
    parser.add_argument("--management-cert", type=str, required=False,
                        help="Path of the management certificate file",
                        default="/opt/xxnetwork/cred/network-management.crt")
    parser.add_argument("--tmp-dir", type=str, required=False,
                        help="Directory for placing temporary files",
                        default="/tmp")
    parser.add_argument("--cmd-dir", type=str, required=False,
                        help="Directory used for saving command file history",
                        default="/opt/xxnetwork/log/cmd")
    parser.add_argument("--wrapper-log", type=str, required=False,
                        help="Path of the wrapper script log file",
                        default="/opt/xxnetwork/log/wrapper.log")

    # cMix/Gateway arguments
    parser.add_argument("--binary-path", type=str, required=True,
                        help="Path of the cMix/Gateway binary")
    parser.add_argument("--config-path", type=str, required=True,
                        help="Path of the cMix/Gateway config file")
    parser.add_argument("--log-path", type=str, required=False,
                        help="Path of the cMix/Gateway log file",
                        default="/opt/xxnetwork/log/xx.log")
    parser.add_argument("--gpu-lib", type=str, required=False,
                        help="Path of the GPU exponentiation library",
                        default="/opt/xxnetwork/lib/libpowmosm75.so")
    parser.add_argument("--gpu-bin", type=str, required=False,
                        help="Path of the GPU bin file",
                        default="/opt/xxnetwork/lib/libpow.fatbin")
    parser.add_argument("--id-path", type=str, required=False,
                        help="Path of the cMix/Gateway ID file",
                        default="/opt/xxnetwork/cred/IDF.json")
    parser.add_argument("--hash-path", type=str, required=False,
                        help="Path to an override file containing custom binary hashes",
                        default=None)
    parser.add_argument("--err-path", type=str, required=False,
                        help="Path of the cMix error recovery file",
                        default="/opt/xxnetwork/logs/cmix-err.log")
    parser.add_argument("--cloudwatch-log-group", type=str, required=False,
                        help="Log group for CloudWatch logging",
                        default="xxnetwork-logs-mainnet")

    # Consensus arguments
    parser.add_argument("--disable-consensus", action="store_true", required=False,
                        help="Disable Consensus integration (For test environments only)",
                        default=False)
    parser.add_argument("--consensus-log", type=str, required=False,
                        help="Path of the Consensus log file",
                        default="/opt/xxnetwork/log/chain.log")
    parser.add_argument("--consensus-cw-group", type=str, required=False,
                        help="Log group for Consensus CloudWatch logging",
                        default="xxnetwork-consensus-mainnet")
    parser.add_argument("--consensus-url", type=str, required=False,
                        help="Listening address for blockchain-provided binary updates",
                        default="ws://localhost:63007")

    args, unknown = parser.parse_known_args()
    args = vars(args)

    # Configure logger
    log.basicConfig(format='[%(levelname)s] %(asctime)s: %(message)s',
                    level=log.DEBUG if args["verbose"] else log.INFO,
                    datefmt='%d-%b-%y %H:%M:%S',
                    filename=args["wrapper_log"])

    # Handle unknown args
    if len(unknown) > 0:
        log.warning(f"Unknown arguments: {unknown}")
    return args


# TARGET CLASS -----------------------------------------------------------------
# Define possible local targets for commands

class Targets:
    BINARY = 'binary'
    GPULIB = 'libpow'
    GPUBIN = 'fatbin'
    WRAPPER = 'wrapper'
    CERT = 'cert'
    LOGGER = 'logger'


# MAIN FUNCTION ---------------------------------------------------------------


def main():
    args = get_args()

    # Ensure network settings are properly configured before allowing a start
    if not check_networking():
        log.error("Unacceptable network settings, refusing to start. "
                  "Run the suggested commands and restart the wrapper service.")
        raise Exception

    # Command line arguments
    log.info(f"Running with configuration: {args}")

    binary_path = args["binary_path"]
    gpulib_path = args["gpu_lib"]
    gpubin_path = args["gpu_bin"]
    is_gateway = args["gateway"]
    management_directory = "gateway" if is_gateway else "server"
    rsa_certificate_path = args["management_cert"]
    s3_management_bucket_name = args["s3_management_bucket"]
    s3_bin_bucket_name = args["s3_bin_bucket"]
    s3_access_key_id = args["s3_access_key"]
    s3_access_key_secret = args["s3_secret"]
    s3_bucket_region = args["s3_region"]
    log_path = args["log_path"]
    wrapper_log_path = args["wrapper_log"]
    err_output_path = args["err_path"]
    id_path = args["id_path"]
    version_file = f"{management_directory}/version.jsonl"
    command_file = f"{management_directory}/command.jsonl"
    tmp_dir = args["tmp_dir"]
    os.makedirs(tmp_dir, exist_ok=True)
    hash_path = args["hash_path"]
    cmd_log_dir = args["cmd_dir"]
    log_grp = args["cloudwatch_log_group"]
    consensus_log = args["consensus_log"]
    consensus_grp = args["consensus_cw_group"]
    consensus_url = args["consensus_url"]
    config_file = args["config_path"]
    disable_consensus = args["disable_consensus"]
    disable_cloudwatch = args["disable_cloudwatch"]

    # The valid "install" paths we can write to, with their local paths for
    # this machine
    valid_paths = {
        Targets.BINARY: os.path.abspath(os.path.expanduser(binary_path)),
        Targets.GPULIB: os.path.abspath(os.path.expanduser(gpulib_path)),
        Targets.GPUBIN: os.path.abspath(os.path.expanduser(gpubin_path)),
        Targets.WRAPPER: os.path.abspath(sys.argv[0]),
        Targets.CERT: rsa_certificate_path,
    }

    # Record the most recent error timestamp to avoid restart loops
    last_error_timestamp = 0
    # Frequency (in seconds) of checking for new commands
    command_frequency = 10

    # Globally keep track of the main process being wrapped
    process = None
    # Globally keep track of the Elixxir logging process
    logging_process = None
    # Globally keep track of the wrapper logging process
    wrapper_logging_process = None
    # Globally keep track of the consensus logging process
    consensus_logging_process = None
    # Globally keep track of the substrate connection
    substrate = None
    # Keep track of current binary hashes for blockchain updates
    current_hashes = dict()

    if disable_consensus:
        # Record the most recent command timestamp to avoid executing duplicate commands
        timestamps = [0, time.time()]
        remotes_paths = [version_file, command_file]
    else:
        # Consensus-specific initialization code
        timestamps = [time.time()]
        remotes_paths = [command_file]

        # Obtain the current wrapper hash in order to prevent update loop
        wrapper_bytes = bytes(open(valid_paths[Targets.WRAPPER], 'rb').read())
        current_hashes[Targets.WRAPPER] = hashlib.blake2s(wrapper_bytes).hexdigest()

        # Node-specific consensus initialization code
        if not is_gateway:
            # Wait for the Node ID file to exist before entering the main loop
            log.info("Waiting on IDF for consensus...")
            while read_cmix_id(id_path) is None:
                time.sleep(command_frequency)

            # Wait for the node to stake before entering the main loop
            substrate = get_substrate_provider(consensus_url)
            log.info("Waiting on consensus ready state...")
            while True:
                while substrate is None:
                    time.sleep(command_frequency)
                    substrate = get_substrate_provider(consensus_url)
                if poll_ready(substrate):
                    log.info("Consensus ready!")
                    break
                time.sleep(command_frequency)

    # CONTROL FLOW -----------------------------------------------------------------

    # Start the various log backup threads
    if not disable_cloudwatch:
        logging_process = start_cw_logger(log_grp, log_path,
                                          id_path, s3_bucket_region,
                                          s3_access_key_id, s3_access_key_secret)
        wrapper_logging_process = start_cw_logger(log_grp, wrapper_log_path,
                                                  id_path, s3_bucket_region,
                                                  s3_access_key_id, s3_access_key_secret)
        if not disable_consensus and not is_gateway:
            consensus_logging_process = start_cw_logger(consensus_grp, consensus_log,
                                                        id_path, s3_bucket_region,
                                                        s3_access_key_id, s3_access_key_secret)

    # Main command/control loop
    log.info(f"Script initialized at {time.time()}")
    while True:
        time.sleep(command_frequency)

        # Handle updates from blockchain, if enabled
        if not disable_consensus:
            if substrate is None:
                # Handle lost connections
                substrate = get_substrate_provider(consensus_url)
            else:
                if not hash_path:
                    # Automatically poll substrate for hashes
                    hashes = poll_cmix_hashes(substrate)
                else:
                    # Manually obtain hashes from file
                    with open(hash_path, "r") as hash_file:
                        hash_file_str = hash_file.readline().strip()
                        hashes = json.loads(hash_file_str)

                if hashes is None:
                    # Connection was lost
                    substrate = None
                elif not hashes:
                    # No hashes available, currently syncing
                    log.debug("Waiting for blockchain node to sync...")
                else:
                    def update_item(update_target):
                        """
                        Helper function for updating targets (excluding cMix binaries)
                        """
                        new_hash = hashes[update_target].replace("0x", "")
                        current_hash = current_hashes.get(
                            update_target, "0000000000000000000000000000000000000000000000000000000000000000")
                        if new_hash != current_hash:
                            log.info(f"{update_target} update required: {current_hash} -> {new_hash}")
                            # Get local destination path
                            install_path = valid_paths[update_target]
                            # Get remote source path
                            remote_path = f"{update_target}/{new_hash}"
                            # Download file to temporary location
                            tmp_path = os.path.join(tmp_dir, os.path.basename(install_path) + ".tmp")
                            download(remote_path, tmp_path,
                                     s3_bin_bucket_name, s3_bucket_region,
                                     s3_access_key_id, s3_access_key_secret)
                            # Perform the update
                            if update(update_target, tmp_path, install_path, new_hash):
                                current_hashes[update_target] = new_hash

                    try:
                        # Check for wrapper updates
                        update_item(Targets.WRAPPER)

                        # Check for GPU library updates
                        if not is_gateway:
                            update_item(Targets.GPUBIN)
                            update_item(Targets.GPULIB)

                        # Check for binary updates
                        new_hash = hashes[management_directory].replace("0x", "")
                        current_hash = current_hashes.get(
                            management_directory, "0000000000000000000000000000000000000000000000000000000000000000")
                        if new_hash != current_hash:
                            log.info(f"{management_directory} update required: {current_hash} -> {new_hash}")
                            # Get local destination path
                            install_path = valid_paths[Targets.BINARY]
                            # Get remote source path
                            remote_path = f"{management_directory}/{new_hash}"
                            # Download file to temporary location
                            tmp_path = os.path.join(tmp_dir, os.path.basename(install_path) + ".tmp")
                            download(remote_path, tmp_path,
                                     s3_bin_bucket_name, s3_bucket_region,
                                     s3_access_key_id, s3_access_key_secret)
                            # Stop the process
                            terminate_process(process)
                            # Perform the update
                            if update(Targets.BINARY, tmp_path, install_path, new_hash):
                                current_hashes[management_directory] = new_hash
                                # Restart the process
                                process = start_binary(valid_paths[Targets.BINARY], log_path,
                                                       ["--config", config_file])
                    except Exception as err:
                        log.error(f"Unable to execute blockchain update: {err}", exc_info=True)

        # If there is a (recently modified) recovered error file present, restart the main process
        if os.path.isfile(err_output_path) and os.path.getmtime(err_output_path) > last_error_timestamp:
            log.warning("Restarting binary due to error...")
            time.sleep(10)

            # Terminate the process if it still exists
            terminate_process(process)
            # Restart the main process
            process = start_binary(valid_paths[Targets.BINARY], log_path,
                                   ["--config", config_file])
            last_error_timestamp = time.time()

        for i, remote_path in enumerate(remotes_paths):
            try:
                # Obtain the latest command file
                local_path = os.path.join(tmp_dir, os.path.basename(remote_path))
                download(remote_path, local_path,
                         s3_management_bucket_name, s3_bucket_region,
                         s3_access_key_id, s3_access_key_secret)

                # Load the command file into JSON
                with open(local_path, 'r') as cmd_file:

                    # Verify the command file signature
                    signed_commands, ok = verify_cmd(cmd_file, rsa_certificate_path)
                    if signed_commands is None:
                        log.error(f"Empty command file: {local_path}")
                        save_cmd(local_path, cmd_log_dir, False, time.time())
                        continue

                    # Handle invalid signature
                    if not ok:
                        log.error(f"Failed to verify signature for {local_path}!", exc_info=True)
                        save_cmd(local_path, cmd_log_dir, ok, time.time())
                        continue

                # Save the command into a log
                timestamp = signed_commands.get("timestamp", 0)
                save_cmd(local_path, cmd_log_dir, ok, timestamp)

                # If the commands occurred before the script, skip
                # Note: We do not update unless we get a command we
                # have verified and can actually attempt to run.
                if timestamp <= timestamps[i]:
                    log.debug(f"Command set with timestamp {timestamp} is outdated, ignoring...")
                    continue

                # Execute the commands in sequence
                for command in signed_commands.get("commands", list()):

                    # If the command does not apply to us, note that and move on
                    if "nodes" in command:
                        node_targets = command.get("nodes", list())
                        # Note: We get the ID for every valid command in case it changes
                        node_id = read_cmix_id(id_path)
                        if node_targets and node_id not in node_targets:
                            log.info(f"Command does not apply to {node_id}")
                            timestamps[i] = timestamp
                            continue

                    # Command applies, so obtain command information
                    command_type = command.get("command", "")
                    target = command.get("target", "")
                    info = command.get("info", dict())
                    log.info(f"Executing command: {command}")

                    # START COMMAND ===========================
                    if command_type == "start":
                        # Decide which type of binary to start
                        if target == Targets.BINARY and (process is None or process.poll() is not None):
                            process = start_binary(valid_paths[Targets.BINARY], log_path,
                                                   ["--config", config_file])
                        elif target == Targets.LOGGER and not disable_cloudwatch:
                            if logging_process is None or not logging_process.is_alive():
                                logging_process = start_cw_logger(log_grp, log_path,
                                                                  id_path, s3_bucket_region,
                                                                  s3_access_key_id, s3_access_key_secret)
                                wrapper_logging_process = start_cw_logger(log_grp, wrapper_log_path,
                                                                          id_path, s3_bucket_region,
                                                                          s3_access_key_id, s3_access_key_secret)
                            if not disable_consensus and not is_gateway \
                                    and (consensus_logging_process is None or not consensus_logging_process.is_alive()):
                                consensus_logging_process = start_cw_logger(consensus_grp, consensus_log,
                                                                            id_path, s3_bucket_region,
                                                                            s3_access_key_id, s3_access_key_secret)

                    # STOP COMMAND ===========================
                    elif command_type == "stop":
                        # Stop the wrapped process
                        if target == Targets.BINARY:
                            terminate_process(process)
                        elif target == Targets.LOGGER:
                            terminate_multiprocess(logging_process)
                            terminate_multiprocess(wrapper_logging_process)
                            terminate_multiprocess(consensus_logging_process)

                    # DELAY COMMAND ===========================
                    elif command_type == "delay":
                        # Delay for the given amount of time
                        # NOTE: Provided in MS, converted to seconds
                        duration = info.get("time", 0)
                        log.info(f"Delaying for {duration}ms...")
                        time.sleep(duration / 1000)

                    # UPDATE COMMAND ===========================
                    elif command_type == "update":

                        # Skip updates of this kind when consensus is enabled
                        if not disable_consensus:
                            log.error("Update command ignored, consensus enabled!")
                            timestamps[i] = timestamp
                            continue

                        # Verify valid install path
                        if target not in valid_paths.keys():
                            log.error(f"Invalid update target: {target}. Expected one of: {valid_paths.keys()}")
                            timestamps[i] = timestamp
                            continue

                        # Get local destination path
                        install_path = valid_paths[target]
                        # Get remote source path
                        remote_path = f'{management_directory}/{info.get("path", "")}'
                        # Download file to temporary location
                        tmp_path = os.path.join(tmp_dir, os.path.basename(install_path) + ".tmp")
                        download(remote_path, tmp_path,
                                 s3_management_bucket_name, s3_bucket_region,
                                 s3_access_key_id, s3_access_key_secret)

                        # Perform the update
                        was_successful = update(target, tmp_path, install_path, info.get("hash", ""))
                        if not was_successful:
                            timestamps[i] = timestamp
                            continue

                    log.info(f"Completed command: {command}")

                # Update the timestamp in order to avoid repetition
                timestamps[i] = timestamp
            except Exception as err:
                log.error(f"Unable to execute commands: {err}", exc_info=True)


if __name__ == "__main__":
    main()
