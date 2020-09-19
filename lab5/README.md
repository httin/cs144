# Lab 5: Build the Internet

## 1. Introduction

At this point you have created several important building blocks of the Internet: in Labs 1 & 2 you built a TCP-compliant transport layer; in Lab 3 you built an Internet router; and in Lab 4 you built a functioning NAT device. In this lab, you are going to put all of these pieces together to build your very own Internet!

> This is a short lab and _**should not**_ take more than 3 hours (if your earlier labs work correctly)! However, that doesn't mean you should start at the last minute!

### Your Task

Your task is to port the `curl` application to work with your Lab 1-4 solutions. You will use `curl` to access a remote web server on the Internet, using cTCP, with packets passing through your IP router and NAT device. If either your cTCP or NAT doesn't work, don't worry; you can use the reference binaries (with minor point deductions, see Grading for details). However, you should take this opportunity to get your previous labs working.

![](https://user-images.githubusercontent.com/61527787/75953854-dc4fe780-5ee4-11ea-9f5b-4b9d8352e221.png)

We will provide you with a stripped down version of `curl` that we call `simple_curl`, without some of `curl`’s bells and whistles. You can use `simple_curl` to download and display webpages:

```
./simple_curl www.google.com
```

In this lab, you will `simple_curl`, using your cTCP implementation, running over your NAT, in order to communicate with an external grading server.

## 2. Implementation Details

After **downloading and recompiling** the new code (see Getting Started), you can run `simple_curl` on any website, which will package up an ethernet frame containing an IP packet containing a cTCP segment, which will be sent to your NAT/router.

![](https://user-images.githubusercontent.com/61527787/75953857-dd811480-5ee4-11ea-8ea9-ee93065c2f19.png)

> If your Labs 2 and 4 work, then your implementation should need 0 extra lines of code!

### Memory Leaks

We expect you to fix all memory leaks and memory errors in your cTCP implementation. This means a clean valgrind report! We expect a mostly-clean valgrind report for NAT (there will be some memory leaks due to the starter code, such as the NAT init code, routing table/interface setup, the ARP cache, and connection-related data structures).

To get your `valgrind` reports, first do the setup as described in **Testing** in the next section, **Getting Started**, except run the following instead of `./sr -n`:
```
sudo valgrind --leak-check=full --show-leak-kinds=all ./sr -n
```

Then, to get a report for cTCP, do the following in a separate terminal:
```
cd ~/lab5/ctcp
sudo valgrind --leak-check=full --show-leak-kinds=all ./ctcp -c 184.72.104.217:80 -p 11111
```

Type the following:
```
GET /
Host: 184.72.104.217
[press enter again]
[Ctrl + D]
```

You will get some kind of error message. That's okay! The resulting valgrind report is what you want. Ctrl + C in both terminals to get both valgrind reports.

Please provide the **ENTIRE** valgrind report in your `README`! That includes the line numbers and messages of all memory leaks.

## 3. Getting Started

### Virtual Machine
Your assignment will run on the same VM as Lab 4.

### Code Setup
Make sure you _**follow these steps exactly and name the folders correctly!**_
Create a new folder for your Lab 5 code:
```
cd ~
mkdir lab5
```

Copy over your cTCP implementation (the entire folder):
```
# for most of you, path/to/ctcp_folder will be ~/lab12
cp -r path/to/ctcp_folder ~/lab5/ctcp
```

Copy over your NAT implementation (the entire folder, including the Mininet stuff, the `router` subfolder, all of it):
```
# for most of you, path/to/nat_folder will be ~/lab4
cp -r path/to/nat_folder ~/lab5/nat
```

The `pox` folder should be a symlink in the `lab5` directory:
```
ln -s /home/cs144/pox ~/lab5/pox
```

Then, download the new starter code:
```
cd ~/lab5
wget http://web.stanford.edu/class/cs144/assignments/lab5/lab5_code.tar.gz
tar -zxvf lab5_code.tar.gz
```

Download the `simple_curl.c` file by visiting [this page](https://web.stanford.edu/class/cs144/cgi-bin/submit/lab5-file.php). This should automatically save the file. If not, you can save this webpage as a file called `simple_curl.c` (make sure to save as "Web Page, HTML only"). Then, copy it to the right directory (or SCP it into the VM):
```
cp path/to/simple_curl.c ~/lab5
```

To verify that you've done this correctly, the following are the new files and changes you should have:

  * `~/lab5/nat/grading_server/` folder
  * `~/lab5/nat/router/rtable`
  * `~/lab5/nat/run_mininet.sh` contains `sudo python lab5.py`
  * `~/lab5/nat/lab5.py`
  * `~/lab5/simple_curl.c`
  * `~/lab5/Makefile`

### Testing

In order to set up this lab, you'll need to have several different terminals open. **You should be in `sudo` for all of them**. To run bash as `sudo`, do the following:
```
sudo bash
```

And type in the VM password, `cs144`.

#### Terminal 1: Mininet

Start Mininet:
```
cd ~/lab5/nat
./run_all.sh
```

#### Terminal 2: NAT

Make and run your NAT:
```
cd ~/lab5/nat/router
make clean
make
./sr -n
```

#### Terminal 3: cTCP and Application

Make your cTCP implementation:
```
cd ~/lab5/ctcp
make clean
make
```

Then make and run `simple_curl`:
```
cd ~/lab5
make clean
make
./simple_curl 184.72.104.217
```

If it works, you should see the following message:
```
Congrats! You've put Lab 5 together!

Enter this token on the submission website: <TOKEN STRING>
```

Keep track of this `<TOKEN STRING>`. You will submit this along with your README for your submission. Note that each time you run `simple_curl`, a different `<TOKEN STRING>` will appear. You want to submit the latest one. You can confirm that it was submitted correctly by visiting the [submission status page](https://web.stanford.edu/class/cs144/cgi-bin/submit/status.php).

#### Stopping Testing

`Ctrl + C` in all terminals. Run `./killall.sh` in Terminal 1.

## 4. Grading and Submission

### Grading

60% of your grade will depend on whether or not you've successfully communicated with the grading server using `simple_curl`. If the communication is successful, then the `<TOKEN STRING>` will appear. 40% of the grade will be from your README. Both the README and the latest `<TOKEN STRING>` must be submitted for a successful submission. You can verify that a success was recorded by visiting the submission status page.

### Reference Binaries

Since we want you to complete Lab 5 even if one of your earlier labs didn’t work properly, we will allow you to use either one of our reference binaries for cTCP and NAT (Labs 2 and 4). You may choose to use _**one**_ of the reference binaries for a 10% deduction in your grade for this lab.

### README

You will submit a `README` file to your submission. This should not be a very long file with no more than 80 characters per column to make it easier to read. It should contain the following:

  * **Reference Binary** - Whether or not you used a reference binary, and if so, which one you used.
  * **Changes** - Describe changes you had to make to your cTCP and/or NAT implementation in order to get this lab to work. If you used a reference binary, then summarize the things that didn't work and the changes you would have needed to get your implementation working. If not changes were required, please state this.
  * **Valgrind** - Submit a valgrind report for **both** your cTCP and NAT, **even if you used a reference binary**. We expect 0 memory leaks for cTCP and very few for the NAT (note that there will be unavoidable leaks from the router state, such as the routing table). If there are any memory leaks left not due to the starter code, we expect an explanation as to why they were not fixed.
  * **Understanding Questions** - Answers to the following questions:
  * Describe/draw the sequence of packets that `simple_curl` sends and receives from the grading server. (Hint: use Wireshark!)
  * The routing table for Lab 5 says:
```
  Destination       Gateway           Mask               Interface
  10.0.1.100        10.0.1.100        255.255.255.255    eth1
  184.72.104.217    184.72.104.217    255.255.255.255    eth2
```
Suppose we wish to set `184.72.104.217` as the default gateway. Write out the new routing table using as few entries as possible.

## 5. FAQ

  * **Sometimes I get an assertion error when running `simple_curl`.**
  
    `simple_curl` picks a random port to communicate out of. This happens occasionally when the port collides with something already in use. Just run `simple_curl` again!
  
  * **How come when I run `./simple_curl.c google.com` it doesn't seem to go through my NAT?**
  
    This is a result of how the Mininet topology is set up. You can get `simple_curl` working from `server1` (instead of `client`) by doing the steps below (thanks James!). Make sure to do this on a fresh VM, as this actually messes with your operating system's IP tables! Super extra credit points if you figure out how to get it working from the `client` (please let us know if you do)! **Note: You do not need to do this for full points on this lab!**

  * Enable IP forwarding
    ```
    sudo echo 1 > /proc/sys/net/ipv4/ip_forward
    ```
  
  * Setup a NAT on `eth1`
    ```
    sudo /sbin/iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
    sudo /sbin/iptables -A FORWARD -i client-eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo /sbin/iptables -A FORWARD -i client-eth0 -o eth1 -j ACCEPT
    ```
  
  * Recompile `sr` with `eth2` as the internal interface (instead of `eth1`).

  * Copy the compiled `simple_curl` from `~/lab5/` to `~/lab5/nat/grading_server`
  
  * In Mininet, run the following command, where `216.58.192.46` is the IP address for `google.com` (DNS does not work)
    ```
    server1 ./simple_curl 216.58.192.46
    ```
