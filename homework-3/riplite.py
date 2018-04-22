from distancevector import DistanceVector
import sys


class Host:
    '''
        This class encapsulate a host (host + router)
    Attr:
        hostname (str)
        my_dv    (DistanceVector): this node's DistanceVector
        other_dv (list): a list of DistanceVector of all other nodes
    '''

    all_hosts = ['h1', 'h2', 'r1', 'r2', 'r3', 'r4']

    def __init__(self, hostname):
        self.hostname = hostname
        self.my_dv = DistanceVector(hostname)
        self.other_dv = []
        // DOTO: finish initialization

    def __str__(self):
        string = self.hostname + "'s distance vector: \n"
        string += self.my_dv.__str__()
        return string


if __name__ == '__main__':
    if len(sys.argv) == 2:
        hostname = sys.argv[1]
        host = Host(hostname)
        print(host)
    else:
        print('Error with parameters')


