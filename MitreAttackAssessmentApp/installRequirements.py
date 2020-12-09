import sys
import subprocess

# adapted from https://www.activestate.com/resources/quick-reads/how-to-install-python-packages-using-a-script/

# read the requirements.txt file
with open('requirements.txt', "r") as f:
    requirements =  list(map(lambda x: x.split("==")[0], f.readlines()))
    #print(requirements)

for r in requirements:
    # implement pip as a subprocess with correct parameters, -m and install:
    subprocess.call([sys.executable, '-m', 'pip', 'install',
    r])

    # process output with an API in the subprocess module:
    reqs = subprocess.check_output([sys.executable, '-m', 'pip',
    'freeze'])
    # get the installed packages - note because the same process is being run,
    # we only 
    installed_packages = [r.decode().split('==')[0] for r in reqs.split()]

print(installed_packages)
