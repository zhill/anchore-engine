import requests
import datetime
import time
import json
import statistics
from anchore_engine.subsys import logger

logger.enable_test_logging()


def test_msg_send(count: int):
    timings = []
    success = 0
    fail = 0

    for i in range(count):
        payload = {"somekey": "somevalue-{}".format(i), "date":"{}".format(datetime.datetime.now())}
        t = time.time()
        r = requests.post('http://localhost:8083/v1/queues/image_watch', auth=('admin', 'foobar'), json=payload)
        if r.status_code == 200:
            success += 1
        else:
            fail += 1

        t = time.time() - t
        timings.append(t)

    print('Success: {} Fail: {}'.format(success, fail))

    return timings


def test_msg_get(count: int):
    timings = []
    success = 0
    fail = 0

    for i in range(count):
        t = time.time()
        r = requests.get('http://localhost:8083/v1/queues/image_watch', auth=('admin', 'foobar'))
        if r.status_code == 200:
            success += 1
        else:
            fail += 1

        t = time.time() - t
        timings.append(t)

    print('Success: {} Fail: {}'.format(success, fail))
    return timings

def test_concurrent():
    pass


if __name__ == '__main__':
    print('Starting test')
    count = 100000
    send_timing = test_msg_send(count)
    rcv_timing = test_msg_get(count)
    print('Send Stats: avg {}, median {}'.format(statistics.mean(send_timing), statistics.median(send_timing)))
    print('Rcv Stats: avg {}, median {}'.format(statistics.mean(rcv_timing), statistics.median(rcv_timing)))
