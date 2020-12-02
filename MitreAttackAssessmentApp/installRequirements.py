import sys
import subprocess

# read the requirements.txt file
with open('requirements.txt', "r") as f:
    requirements =  list(map(lambda x: x.split("==")[0], f.readlines()))
    #print(requirements)

for r in requirements:
    # implement pip as a subprocess:
    subprocess.call([sys.executable, '-m', 'pip', 'install',
    r])

    # process output with an API in the subprocess module:
    reqs = subprocess.check_output([sys.executable, '-m', 'pip',
    'freeze'])
    installed_packages = [r.decode().split('==')[0] for r in reqs.split()]

print(installed_packages)
