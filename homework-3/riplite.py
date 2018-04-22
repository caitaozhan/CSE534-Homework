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
        self.neighbor     = []
        self.non_neighbor = []

        for host in self.all_hosts:
            for distance in self.my_dv.dv:
                if host == distance.Dest:
                    self.neighbor.append(host)
                    break
                elif host == self.hostname:
                    break
            else: # not a neighbor of this host, also not itself
                self.non_neighbor.append(host)

        for host in self.non_neighbor:
            self.my_dv.add_distance(DistanceVector.Distance(Dest=host, Cost=9999, Next=''))


    def __str__(self):
        string = self.hostname + "'s distance vector: \n"
        string += self.my_dv.__str__()
        return string


if __name__ == '__main__':
    h1 = Host('h1')
    h2 = Host('h2')
    r1 = Host('r1')
    r2 = Host('r2')
    r3 = Host('r3')
    r4 = Host('r4')
    print h1
    print h2
    print r1
    print r2
    print r3
    print r4

    '''
    if len(sys.argv) == 2:
        hostname = sys.argv[1]
        host = Host(hostname)
        print(host)
    else:
        print('Error with parameters')
    '''

