import libuser
import unittest

def prompt_callback(prompts):
    for p in prompts:
        if p.key == 'ldap/password':
            p.value = 'password'
        else:
            p.value = p.default_value

# Test case order matches the order of function pointers in struct lu_module
class Tests(unittest.TestCase):
    def setUp(self):
        self.a = libuser.admin(prompt = prompt_callback)

    # testUsesElevatedPrivileges
    # Not provided in Python bindings

    def testUserLookupName(self):
        e = self.a.initUser('user2_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user2_1')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user2_1'])
        del e
        e = self.a.lookupUserByName('user2_does_not_exist')
        self.assertEqual(e, None)

    def testUserLookupId(self):
        e = self.a.initUser('user3_1')
        self.a.addUser(e, False, False)
        uid = e[libuser.UIDNUMBER][0]
        del e
        e = self.a.lookupUserById(uid)
        self.assert_(e)
        self.assertEqual(e[libuser.UIDNUMBER], [uid])
        del e
        e = self.a.lookupUserById(999999)
        self.assertEqual(e, None)

    # testUserDefault
    # There is little to test, in addition most is configurable

    # testUserAddPrep:
    # Nothing to test

    def testUserAdd1(self):
        # A minimal case
        e = self.a.initUser('user6_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_1')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user6_1'])

    def testUserAdd2(self):
        # A maximal case
        e = self.a.initUser('user6_2')
        e[libuser.USERNAME] = 'user6_2username'
        e[libuser.USERPASSWORD] = '!!baduser6_2' # Should be ignored
        e[libuser.UIDNUMBER] = 4237
        e[libuser.GIDNUMBER] = 3742
        e[libuser.GECOS] = 'Full Name,Office,1234,4321'
        e[libuser.HOMEDIRECTORY] = '/home/user6_2home'
        e[libuser.LOGINSHELL] = '/sbin/nologinuser6_2'
        e[libuser.SHADOWPASSWORD] = '!!user6_2'
        e[libuser.SHADOWLASTCHANGE] = 12681
        e[libuser.SHADOWMIN] = 5
        e[libuser.SHADOWMAX] = 98765
        e[libuser.SHADOWWARNING] = 10
        e[libuser.SHADOWINACTIVE] = 8
        e[libuser.SHADOWEXPIRE] = 9
        e[libuser.SHADOWFLAG] = 255
        e[libuser.COMMONNAME] = 'Common Name'
        e[libuser.GIVENNAME] = 'Given'
        e[libuser.SN] = 'Surname'
        e[libuser.ROOMNUMBER] = 404
        e[libuser.TELEPHONENUMBER] = 1234
        e[libuser.HOMEPHONE] = 4321
        e[libuser.EMAIL] = 'user6_2@example.com'
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_2username')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user6_2username'])
        self.assertEqual(e[libuser.UIDNUMBER], [4237])
        self.assertEqual(e[libuser.GIDNUMBER], [3742])
        self.assertEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/user6_2home'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser6_2'])
        # The ambiguous userPassword attribute is read as LU_USERPASSWORD,
        # not LU_SHADOWPASSWORD
        self.assertEqual(e[libuser.USERPASSWORD], ['!!user6_2'])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [12681])
        self.assertEqual(e[libuser.SHADOWMIN], [5])
        self.assertEqual(e[libuser.SHADOWMAX], [98765])
        self.assertEqual(e[libuser.SHADOWWARNING], [10])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [8])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [9])
        self.assertEqual(e[libuser.SHADOWFLAG], [255])
        self.assertEqual(e[libuser.COMMONNAME], ['Common Name'])
        self.assertEqual(e[libuser.GIVENNAME], ['Given'])
        self.assertEqual(e[libuser.SN], ['Surname'])
        self.assertEqual(e[libuser.ROOMNUMBER], [404])
        self.assertEqual(e[libuser.TELEPHONENUMBER], [1234])
        self.assertEqual(e[libuser.HOMEPHONE], [4321])
        # Not stored by our LDAP module
        # self.assertEqual(e[libuser.EMAIL], ['user6_2@example.com'])

    def testUserAdd3(self):
        # Schema violation
        e = self.a.initUser('user6_3')
        e[libuser.GIVENNAME] = 'Given'
        # e[libuser.SN] required by inetOrgPerson schema, but not provided
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)

    def testUserMod1(self):
        # A minimal case
        e = self.a.initUser('user7_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_1')
        self.assertNotEqual(e[libuser.GECOS], ['user7newGECOS'])
        e[libuser.GECOS] = 'user7newGECOS'
        self.a.modifyUser(e, False)
        del e
        e = self.a.lookupUserByName('user7_1')
        self.assertEqual(e[libuser.GECOS], ['user7newGECOS'])

    def testUserMod2(self):
        # A maximal case, including renaming.
        e = self.a.initUser('user7_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_2')
        self.assertNotEqual(e[libuser.USERNAME], ['user7_2username'])
        e[libuser.USERNAME] = 'user7_2username'
        self.assertNotEqual(e[libuser.UIDNUMBER], [4237])
        e[libuser.UIDNUMBER] = 4237
        self.assertNotEqual(e[libuser.GIDNUMBER], [3742])
        e[libuser.GIDNUMBER] = 3742
        self.assertNotEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        e[libuser.GECOS] = 'Full Name,Office,1234,4321'
        self.assertNotEqual(e[libuser.HOMEDIRECTORY], ['/home/user7_2home'])
        e[libuser.HOMEDIRECTORY] = '/home/user7_2home'
        self.assertNotEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser7_2'])
        e[libuser.LOGINSHELL] = '/sbin/nologinuser7_2'
        # The ambiguous userPassword attribute is read as LU_USERPASSWORD,
        # not LU_SHADOWPASSWORD
        e[libuser.SHADOWPASSWORD] = '!!user7_2'
        self.assertNotEqual(e[libuser.SHADOWLASTCHANGE], [12681])
        e[libuser.SHADOWLASTCHANGE] = 12681
        self.assertNotEqual(e[libuser.SHADOWMIN], [5])
        e[libuser.SHADOWMIN] = 5
        self.assertNotEqual(e[libuser.SHADOWMAX], [98765])
        e[libuser.SHADOWMAX] = 98765
        self.assertNotEqual(e[libuser.SHADOWWARNING], [10])
        e[libuser.SHADOWWARNING] = 10
        self.assertNotEqual(e[libuser.SHADOWINACTIVE], [8])
        e[libuser.SHADOWINACTIVE] = 8
        self.assertNotEqual(e[libuser.SHADOWEXPIRE], [9])
        e[libuser.SHADOWEXPIRE] = 9
        self.assertNotEqual(e[libuser.SHADOWFLAG], [255])
        e[libuser.SHADOWFLAG] = 255
        self.a.modifyUser(e, False)
        del e
        e = self.a.lookupUserByName('user7_2')
        self.assertEqual(e, None)
        del e
        e = self.a.lookupUserByName('user7_2username')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user7_2username'])
        self.assertEqual(e[libuser.UIDNUMBER], [4237])
        self.assertEqual(e[libuser.GIDNUMBER], [3742])
        self.assertEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/user7_2home'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser7_2'])
        # The ambiguous userPassword attribute is read as LU_USERPASSWORD,
        # not LU_SHADOWPASSWORD
        self.assertEqual(e[libuser.USERPASSWORD], ['!!user7_2'])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [12681])
        self.assertEqual(e[libuser.SHADOWMIN], [5])
        self.assertEqual(e[libuser.SHADOWMAX], [98765])
        self.assertEqual(e[libuser.SHADOWWARNING], [10])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [8])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [9])
        self.assertEqual(e[libuser.SHADOWFLAG], [255])

    def tearDown(self):
        del self.a
        
if __name__ == '__main__':
    unittest.main()
