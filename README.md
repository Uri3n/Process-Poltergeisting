# Process-Poltergeisting
## A PoC That Uses A Windows File Stream Exploit To Perform A Variation Of Process Ghosting.

# Background
**Process Ghosting** is a technique that has been around for quite some time. 
Long story short, it involves writing a malicious PE file into a temp file on disk,
creating a section object from it, and then quickly deleting the file along with its contents to
avoid file scanners and further investigation. This section object, which is mapped as SEC_IMAGE,
indicates backed memory belonging to an executable file. It is then utilized alongside the
undocumented syscall **NtCreateProcessEx** to create a process from this section. You will now have a payload
that resides entirely in backed memory, without needing to allocate this memory ourselves. The problem, however,
is that processes created with **NtCreateProcessEx** do not initialize with a main thread, or even any threads at all.
This means that a remote thread must be created, which is almost guaranteed to get you caught against most security solutions.

# Poltergeisting
**Process Poltergeisting** is a variation of Ghosting that allows for the same benefits without requiring remote thread
creation. It works by first writing a malicious PE file into a temporary one, much like Ghosting. However, instead of deleting the file
right away, we create a process from it immediately, using the fully documented and supported win32 function, **CreateProcessW**.

### Okay, so how do we delete the file then?
We can delete the file afterward by abusing Windows alternate file streams. When you attempt to delete a file on disk, Windows will first check
to see if any processes are running that are associated with said file, and prevents deletion if so. However, by altering the name of the main file stream, **$DATA**,
we can effectively create an entirely new directory entry that is still associated with the same disk contents.
For example, if I rename the main data stream of **myFile.txt** to **:MyNewStream**, there are now effectively two directory 
entries that exist: **myFile.txt:$DATA** and **myFile.txt:MyNewStream**. At this point, running processes will still be using the old directory entry, even though the name
of the main file stream has changed. Because of this, we are now free to delete the contents of the file, because accessing it from this point forth will provide us with the second
directory entry we have just created, which is still associated with the same disk contents.

### Spoofing Process Information
Similarly to Ghosting, I performed some basic spoofing on the child process in this PoC to make it appear more legitimate, making it seem as though
it's a harmless RuntimeBroker process.
![PG1](https://github.com/Uri3n/Process-Poltergeisting/assets/153572153/ef4d0066-5587-43e6-9957-618220f51cc0)

As you can see, our malicious process is "verified" by the Microsoft Corporation. Wow! Very Legit!

### Payload Execution
Something extremely important to note is that the Windows loader performs some basic antimalware scanning before it creates a process. If we attempt to put a highly signatured payload
inside of the PE we write into the temp file, this will get flagged right away by Defender. It's important to note though that this is NOT the same as the periodic on-disk scanning that 
Defender usually performs. This happens right before the loader loads an executable into memory. 

### How do we get around this? Wouldn't this mean we would need to create executable memory ourselves after the fact?
The Windows loader utilizes the **Characteristics** bitmask inside of a PE file's section headers to determine the appropriate memory permissions for a given executable's sections.
It is possible to alter this bitmask by specifying to the MSVC compiler that you'd like different memory permissions for your image sections. Therefore, we can utilize the **/SECTION**
command to instruct the linker to make the .text section of our file **read/write/execute** by default. The command is as follows: **/SECTION:.text:ERW**.
Once we have a PE compiled with this flag, the .text section will be RWX once loaded by default. The only thing we need to do after we ghost the file on disk is to simply write our payload
into the pre-existing RWX section, and run it. In this case, I utilized Early Bird injection and queued the payload as an APC routine to the process' suspended main thread.

![PG2](https://github.com/Uri3n/Process-Poltergeisting/assets/153572153/b225886b-38db-40f1-a8ef-db907cdc5204)

This is not a perfect technique by any means at all. However, I thought it was interesting enough to post. I hope you may learn something from this repository.
Goodbye.
