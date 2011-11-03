
class VerhoeffChecksum():
    # Python code from wikibooks
    # http://en.wikibooks.org/wiki/Algorithm_Implementation/Checksums/Verhoeff_Algorithm
    # @see <a
    # href="http://en.wikipedia.org/wiki/Verhoeff_algorithm/">More
    # Info</a> @see <a
    # href="http://en.wikipedia.org/wiki/Dihedral_group">Dihedral
    # Group</a> @see <a
    # href="http://mathworld.wolfram.com/DihedralGroupD5.html">Dihedral
    # Group Order 10</a> @author Hermann Himmelbauer
 
    verhoeff_table_d = (
        (0,1,2,3,4,5,6,7,8,9),
        (1,2,3,4,0,6,7,8,9,5),
        (2,3,4,0,1,7,8,9,5,6),
        (3,4,0,1,2,8,9,5,6,7),
        (4,0,1,2,3,9,5,6,7,8),
        (5,9,8,7,6,0,4,3,2,1),
        (6,5,9,8,7,1,0,4,3,2),
        (7,6,5,9,8,2,1,0,4,3),
        (8,7,6,5,9,3,2,1,0,4),
        (9,8,7,6,5,4,3,2,1,0))
    verhoeff_table_p = (
        (0,1,2,3,4,5,6,7,8,9),
        (1,5,7,6,2,8,3,0,9,4),
        (5,8,0,3,7,9,6,1,4,2),
        (8,9,1,6,0,4,3,5,2,7),
        (9,4,5,3,1,2,6,8,7,0),
        (4,2,8,6,5,7,3,9,0,1),
        (2,7,9,3,8,0,6,4,1,5),
        (7,0,4,6,9,1,3,2,5,8))
    verhoeff_table_inv = (0,4,3,2,1,5,6,7,8,9)

    def calcsum(self, number):
        """For a given number returns a Verhoeff checksum digit"""
        c = 0
        for i, item in enumerate(reversed(str(number))):
            c = self.verhoeff_table_d[c][self.verhoeff_table_p[(i+1)%8][int(item)]]
        return self.verhoeff_table_inv[c]
        
    def checksum(self,number):
        """For a given number generates a Verhoeff digit and
        returns number + digit"""
        c = 0
        for i, item in enumerate(reversed(str(number))):
            c = self.verhoeff_table_d[c][self.verhoeff_table_p[i % 8][int(item)]]
        return c
 
    def generateVerhoeff(self, number):
        """For a given number returns number + Verhoeff checksum digit"""
        return "%s%s" % (number, self.calcsum(number))
 
    def validateVerhoeff(self, number):
        """Validate Verhoeff checksummed number (checksum is last digit)"""
        return self.checksum(number) == 0
 
if __name__ == '__main__':
    
    v = VerhoeffChecksum()

    # Some tests and also usage examples
    assert v.calcsum('75872') == 2
    assert v.checksum('758722') == 0
    assert v.calcsum('12345') == 1
    assert v.checksum('123451') == 0
    assert v.calcsum('142857') == 0
    assert v.checksum('1428570') == 0
    assert v.calcsum('123456789012') == 0
    assert v.checksum('1234567890120') == 0
    assert v.calcsum('8473643095483728456789') == 2
    assert v.checksum('84736430954837284567892') == 0
    assert v.generateVerhoeff('12345') == '123451'
    assert v.validateVerhoeff('123451') == True
    assert v.validateVerhoeff('122451') == False
    assert v.validateVerhoeff('128451') == False


