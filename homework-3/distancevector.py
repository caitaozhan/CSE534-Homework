from collections import namedtuple

class DistanceVector:
    '''This class encapsulates the distance vector
    '''
    Distance = namedtuple('Distance', ['Dest', 'Cost', 'Next'])

    def __init__(self, hostname):
        '''
            Read neighbor file and init the distance vector
        '''

        self._dv = []  # a distance vector is essentially a list

        with open('neighbor/' + hostname, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip().split(' ')
                neighbor = line[0]
                weight   = line[1]
                self._dv.append(self.Distance(Dest=neighbor, Cost=weight, Next=neighbor))


    def __str__(self):
        string = ''
        for distance in self._dv:
            string += str(distance) + '\n'
        return string


if __name__ == '__main__':
    dv = DistanceVector('r1')
    print(dv)
