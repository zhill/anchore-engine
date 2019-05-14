"""
Generic utilities
"""
import datetime
import hashlib
import json
import platform
import subprocess
import uuid
import threading
from collections import OrderedDict
from contextlib import contextmanager
from operator import itemgetter
import time
import os
import re

from anchore_engine.subsys import logger


K_BYTES = 1024
M_BYTES = 1024 * K_BYTES
G_BYTES = 1024 * M_BYTES
T_BYTES = 1024 * G_BYTES

SIZE_UNITS = {
    'kb': K_BYTES,
    'mb': M_BYTES,
    'gb': G_BYTES,
    'tb': T_BYTES
}

BYTES_REGEX = re.compile(r'^([0-9]+)([kmgt]b)?$')


def process_cve_status(old_cves_result=None, new_cves_result=None):
    """
    Returns the diff of two cve results. Only compares two valid results, if either is None or empty, will return empty.

    :param cve_record:
    :return: dict with diff results: {'added': [], 'updated': [], 'removed': []}
    """

    if not new_cves_result or not old_cves_result:
        return {} # Nothing to do

    try:
        if 'multi' in old_cves_result:
            old_cve_header = old_cves_result['multi']['result']['header']
            old_cve_rows = old_cves_result['multi']['result']['rows']
        else:
            # element 0 is the image id
            old_cve_header = old_cves_result[0]['result']['header']
            old_cve_rows = old_cves_result[0]['result']['rows']
    except:
        old_cve_header = None
        old_cve_rows = None

    try:
        if 'multi' in new_cves_result:
            new_cve_header = new_cves_result['multi']['result']['header']
            new_cve_rows = new_cves_result['multi']['result']['rows']
        else:
            # element 0 is the image id
            new_cve_header = new_cves_result[0]['result']['header']
            new_cve_rows = new_cves_result[0]['result']['rows']
    except:
        new_cve_header = None
        new_cve_rows = None

    summary_elements = [
        "CVE_ID",
        "Severity",
        "Vulnerable_Package",
        "Fix_Available",
        "URL",
        "Package_Name",
        "Package_Version",
        "Package_Type",
        "Feed",
        "Feed_Group",
    ]

    if new_cve_rows is None or old_cve_rows is None:
        return {}

    new_cves = pivot_rows_to_keys(new_cve_header, new_cve_rows, key_names=['CVE_ID', 'Vulnerable_Package'],
                                  whitelist_headers=summary_elements)
    old_cves = pivot_rows_to_keys(old_cve_header, old_cve_rows, key_names=['CVE_ID', 'Vulnerable_Package'],
                                  whitelist_headers=summary_elements)
    diff = item_diffs(old_cves, new_cves)

    return diff


def item_diffs(old_items=None, new_items=None):
    """
    Given previous cve-scan output and new cve-scan output for the same image, return a diff as a map.
    Keys:
    {
        'added': [],
        'removed': [],
        'updated': []
    }

    :param old_cves: mapped cve results (from map_rows() result) from previous value
    :param new_cves: mapped cve results (from map_rows() result) from current_value
    :return: dictionary object with results
    """

    if not old_items:
        old_items = {}

    if not new_items:
        new_items = {}

    new_ids = set(new_items.keys())
    old_ids = set(old_items.keys())
    added = [new_items[x] for x in new_ids.difference(old_ids)]
    removed = [old_items[x] for x in old_ids.difference(new_ids)]
    intersected_ids = new_ids.intersection(old_ids)
    updated = [new_items[x] for x in [x for x in intersected_ids if new_items[x] != old_items[x]]]

    return {
        'added': added,
        'removed': removed,
        'updated': updated
    }


def list_to_map(item_list, key_name):
    """
    Given a list of dicts/objects return a dict mapping item[key_name] -> item

    :param item_list:
    :param key_name:
    :return:
    """

    return {x.pop(key_name): x for x in item_list}


def map_rows(header_list, row_list):
    """
    :param header_list: list of names ordered to match row data, provides names for each row
    :param row_list: list of row tuples/lists with each tuple/list in same order as header_list
    :return: list of dicts with named values instead of tuples
    """

    header_map = {v: header_list.index(v) for v in header_list}
    mapped = [{key: item[header_map[key]] for key in header_map} for item in row_list]
    return mapped


def pivot_rows_to_keys(header_list, row_list, key_names=[], whitelist_headers=None):
    """
    Slightly more direct converter for header,row combo into a dict of objects

    :param header_list:
    :param row_list:
    :param key_name:
    :return:
    """
    header_map = {v: header_list.index(v) for v in
                  [x for x in header_list if not whitelist_headers or x in whitelist_headers or x in key_names]}

    key_idxs = []
    for key_name in key_names:
        key_idxs.append(header_map[key_name])

    #key_idx = header_map[key_name]
    #return {"{}{}".format(x[key_idx],x[keya_idx]): {k: x[v] for k, v in list(header_map.items())} for x in row_list}

    return {":".join(itemgetter(*key_idxs)(x)): {k: x[v] for k, v in list(header_map.items())} for x in row_list}


def filter_record_keys(record_list, whitelist_keys):
    """
    Filter the list records to remove verbose entries and make it suitable for notification format
    :param record_dict: dict containing values to process
    :param whitelist_keys: keys to leave in the record dicts
    :return: a new list with dicts that only contain the whitelisted elements
    """

    filtered = [{k: v for k, v in [y for y in list(x.items()) if y[0] in whitelist_keys]} for x in record_list]
    return filtered

def run_sanitize(cmd_list):
    def shellcheck(x):
        if not re.search("[;&<>]", x):
            return(x)
        else:
            raise Exception("bad character in shell input")

    return([x for x in cmd_list if shellcheck(x)])

def run_command_list(cmd_list, env=None):
    """
    Run a command from a list with optional environemnt and return a tuple (rc, stdout_str, stderr_str)
    :param cmd_list: list of command e.g. ['ls', '/tmp']
    :param env: dict of env vars for the environment if desired. will replace normal env, not augment
    :return: tuple (rc_int, stdout_str, stderr_str)
    """

    rc = -1
    sout = serr = None
    cmd_list = run_sanitize(cmd_list)
    try:
        if env:
            pipes = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        else:
            pipes = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = pipes.communicate()
        rc = pipes.returncode
    except Exception as err:
        raise err

    #sout = ensure_str(sout)
    #serr = ensure_str(serr)

    return(rc, sout, serr)


def run_command(cmdstr, env=None):
    return run_command_list(cmdstr.split(), env=env)


def manifest_to_digest(rawmanifest):
    from anchore_engine.clients.skopeo_wrapper import manifest_to_digest_shellout

    ret = None
    d = json.loads(rawmanifest, object_pairs_hook=OrderedDict)
    if d['schemaVersion'] != 1:
        ret = "sha256:" + str(hashlib.sha256(rawmanifest.encode('utf-8')).hexdigest())
    else:
        ret = manifest_to_digest_shellout(rawmanifest)

    ret = ensure_str(ret)
    return(ret)


def get_threadbased_id(guarantee_uniq=False):
    """
    Returns a string for use with acquire() calls optionally. Constructs a consistent id from the platform node, process_id and thread_id

    :param guarantee_uniq: bool to have the id generate a uuid suffix to guarantee uniqeness between invocations even in the same thread
    :return: string
    """

    return '{}:{}:{}:{}'.format(platform.node(), os.getpid(), str(threading.get_ident()),uuid.uuid4().hex if guarantee_uniq else '')

class AnchoreException(Exception):

    def to_dict(self):
        return {self.__class__.__name__: dict((key, value) for key, value in vars(self).items() if not key.startswith('_'))}

def parse_dockerimage_string(instr):
    host = None
    port = None
    repo = None
    tag = None
    registry = None
    repotag = None
    fulltag = None
    fulldigest = None
    digest = None
    imageId = None

    logger.debug("input string to parse: {}".format(instr))
    instr = instr.strip()
    bad_chars = re.findall(r"[^a-zA-Z0-9@:/_\.\-]", instr)
    if bad_chars:
        raise ValueError("bad character(s) {} in dockerimage string input ({})".format(bad_chars, instr))

    if re.match(r"^sha256:.*", instr):
        registry = 'docker.io'
        digest = instr

    elif len(instr) == 64 and not re.findall(r"[^0-9a-fA-F]+",instr):
        imageId = instr
    else:

        # get the host/port
        patt = re.match(r"(.*?)/(.*)", instr)
        if patt:
            a = patt.group(1)
            remain = patt.group(2)
            patt = re.match(r"(.*?):(.*)", a)
            if patt:
                host = patt.group(1)
                port = patt.group(2)
            elif a == 'docker.io':
                host = 'docker.io'
                port = None
            elif a in ['localhost', 'localhost.localdomain', 'localbuild']:
                host = a
                port = None
            else:
                patt = re.match(r".*\..*", a)
                if patt:
                    host = a
                else:
                    host = 'docker.io'
                    remain = instr
                port = None

        else:
            host = 'docker.io'
            port = None
            remain = instr

        # get the repo/tag
        patt = re.match(r"(.*)@(.*)", remain)
        if patt:
            repo = patt.group(1)
            digest = patt.group(2)
        else:
            patt = re.match(r"(.*):(.*)", remain)
            if patt:
                repo = patt.group(1)
                tag = patt.group(2)
            else:
                repo = remain
                tag = "latest"

        if not tag:
            tag = "latest"

        if port:
            registry = ':'.join([host, port])
        else:
            registry = host

        if digest:
            repotag = '@'.join([repo, digest])
        else:
            repotag = ':'.join([repo, tag])

        fulltag = '/'.join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + '/' + repo + '@' + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret['host'] = host
    ret['port'] = port
    ret['repo'] = repo
    ret['tag'] = tag
    ret['registry'] = registry
    ret['repotag'] = repotag
    ret['fulltag'] = fulltag
    ret['digest'] = digest
    ret['fulldigest'] = fulldigest
    ret['imageId'] = imageId

    if ret['fulldigest']:
        ret['pullstring'] = ret['fulldigest']
    elif ret['fulltag']:
        ret['pullstring'] = ret['fulltag']
    else:
        ret['pullstring'] = None

    return(ret)


def ensure_bytes(obj):
    return obj.encode('utf-8') if type(obj) != bytes else obj


def ensure_str(obj):
    return str(obj, 'utf-8') if type(obj) != str else obj


rfc3339_date_fmt = '%Y-%m-%dT%H:%M:%SZ'
rfc3339_date_input_fmts = ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S:%fZ']

def rfc3339str_to_epoch(rfc3339_str):
    return int(rfc3339str_to_datetime(rfc3339_str).timestamp())

def rfc3339str_to_datetime(rfc3339_str):
    """
    Convert the rfc3339 formatted string (UTC only) to a datatime object with tzinfo explicitly set to utc. Raises an exception if the parsing fails.

    :param rfc3339_str:
    :return:
    """

    ret = None
    for fmt in rfc3339_date_input_fmts:
        try:
            ret = datetime.datetime.strptime(rfc3339_str, fmt)
            # Force this since the formats we support are all utc formats, to support non-utc
            if ret.tzinfo is None:
                ret = ret.replace(tzinfo=datetime.timezone.utc)
            continue
        except:
            pass

    if ret is None:
        raise Exception("could not convert input created_at value ({}) into datetime using formats in {}".format(rfc3339_str, rfc3339_date_input_fmts))

    return(ret)

def datetime_to_rfc3339(dt_obj):
    """
    Simple utility function. Expects a UTC input, does no tz conversion

    :param dt_obj:
    :return:
    """

    return dt_obj.strftime(rfc3339_date_fmt)


def epoch_to_rfc3339(epoch_int):
    """
    Convert an epoch int value to a RFC3339 datetime string

    :param epoch_int:
    :return:
    """
    return datetime_to_rfc3339(datetime.datetime.utcfromtimestamp(epoch_int))


def convert_bytes_size(size_str):
    """
    Converts a size string to an int. Allows trailing units

    e.g. "10" -> 10, "1kb" -> 1024, "1gb" -> 1024*1024*1024
    :param size_str:
    :return:
    """

    m = BYTES_REGEX.fullmatch(size_str.lower())
    if m:
        number = int(m.group(1))

        if m.group(2) is not None:
            unit = m.group(2)
            conversion = SIZE_UNITS.get(unit)
            if conversion:
                return conversion * number
        return number
    else:
        raise ValueError("Invalid size string: {}".format(size_str))


def convert_docker_history_to_dockerfile(docker_history_entries):
    """
    Convert a docker history to a pseudo-dockerfile by transforming the entries and adding a FROM scratch line

    :param docker_history_entries: list of docker history dicts, one for each line
    :return: str of dockerfile
    """

    dockerfile_contents = "FROM scratch\n"
    for hel in docker_history_entries:
        patt = re.match(r"^/bin/sh -c #\(nop\) +(.*)", hel['CreatedBy'])
        if patt:
            cmd = patt.group(1)
        elif hel['CreatedBy']:
            cmd = "RUN " + hel['CreatedBy']
        else:
            cmd = None
        if cmd:
            dockerfile_contents = dockerfile_contents + cmd + "\n"

    return dockerfile_contents