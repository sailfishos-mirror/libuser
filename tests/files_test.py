import crypt
import libuser
import unittest

LARGE_ID = 2147483648

# Test case order matches the order of function pointers in struct lu_module
class Tests(unittest.TestCase):
    def setUp(self):
        self.a = libuser.admin()

    # testUsesElevatedPrivileges
    # Not provided in Python bindings

    def testUserLookupName1(self):
        e = self.a.initUser('user2_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user2_1')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user2_1'])
        del e
        e = self.a.lookupUserByName('user2_does_not_exist')
        self.assertEqual(e, None)

    def testUserLookupName2(self):
        # Handling of empty/default values
        e = self.a.lookupUserByName('empty_user')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['empty_user'])
        self.assertEqual(e[libuser.USERPASSWORD], [''])
        self.assertEqual(e[libuser.UIDNUMBER], [42])
        self.assertEqual(e[libuser.GIDNUMBER], [43])
        self.assertEqual(e[libuser.GECOS], [''])
        self.assertEqual(e[libuser.HOMEDIRECTORY], [''])
        self.assertEqual(e[libuser.LOGINSHELL], ['/bin/bash'])
        self.assertEqual(e[libuser.SHADOWNAME], ['empty_user'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [''])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [1000])
        self.assertEqual(e[libuser.SHADOWMIN], [0])
        self.assertEqual(e[libuser.SHADOWMAX], [99999])
        self.assertEqual(e[libuser.SHADOWWARNING], [7])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [-1])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [-1])
        self.assertEqual(e[libuser.SHADOWFLAG], [-1])

    def testUserLookupName3(self):
        # Handling of values that appear to be numbers
        e = self.a.lookupUserByName('077')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['077'])
        self.assertEqual(e[libuser.USERPASSWORD], ['077'])
        self.assertEqual(e[libuser.UIDNUMBER], [230])
        self.assertEqual(e[libuser.GIDNUMBER], [231])
        self.assertEqual(e[libuser.GECOS], ['077'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['077'])
        self.assertEqual(e[libuser.LOGINSHELL], ['077'])
        self.assertEqual(e[libuser.SHADOWNAME], ['077'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['077'])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [77])
        self.assertEqual(e[libuser.SHADOWMIN], [77])
        self.assertEqual(e[libuser.SHADOWMAX], [77])
        self.assertEqual(e[libuser.SHADOWWARNING], [77])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [77])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [77])
        self.assertEqual(e[libuser.SHADOWFLAG], [77])

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
        del e
        e = self.a.lookupUserById(LARGE_ID + 310)
        self.assertEqual(e, None)

    def testUserDefault(self):
        # Test the default/LU_USERNAME = %n preserves usernames that appear to
        # be numbers
        e = self.a.initUser('077')
        self.assertEqual(e[libuser.USERNAME], ['077'])

    # Setting of USERPASSWORD to "x" tested below
    def testUserAddPrep(self):
        # Nothing to do with the "files" module: tests of lu_name_allowed()
        e = self.a.initUser('very_long_name_123456789_123456789_123456789')
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)
        del e
        e = self.a.initUser('non_ascii_name_\xff')
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)
        del e
        e = self.a.initUser('nonprintable_name_\x0a')
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)
        del e
        e = self.a.initUser('nonprintable_name_\x7f')
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)
        del e
        e = self.a.initUser('name with spaces')
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)
        del e
        e = self.a.initUser('-name_with_hyphen')
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)
        del e
        e = self.a.initUser('0.allowed-Name-TEST_0123456789$')
        self.a.addUser(e, False, False)

    def testUserAdd1(self):
        # A minimal case
        e = self.a.initUser('user6_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_1')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user6_1'])
        # Default values
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/bin/bash'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])
        self.assertEqual(e[libuser.SHADOWMIN], [0])
        self.assertEqual(e[libuser.SHADOWMAX], [99999])
        self.assertEqual(e[libuser.SHADOWWARNING], [7])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [-1])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [-1])
        self.assertEqual(e[libuser.SHADOWFLAG], [-1])

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
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.UIDNUMBER], [4237])
        self.assertEqual(e[libuser.GIDNUMBER], [3742])
        self.assertEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/user6_2home'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser6_2'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!user6_2'], )
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [12681])
        self.assertEqual(e[libuser.SHADOWMIN], [5])
        self.assertEqual(e[libuser.SHADOWMAX], [98765])
        self.assertEqual(e[libuser.SHADOWWARNING], [10])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [8])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [9])
        self.assertEqual(e[libuser.SHADOWFLAG], [255])
        # Not stored by the modules
        # self.assertEqual(e[libuser.COMMONNAME], ['Common Name'])
        # self.assertEqual(e[libuser.GIVENNAME], ['Given'])
        # self.assertEqual(e[libuser.SN], ['Surname'])
        # self.assertEqual(e[libuser.ROOMNUMBER], [404])
        # self.assertEqual(e[libuser.TELEPHONENUMBER], [1234])
        # self.assertEqual(e[libuser.HOMEPHONE], [4321])
        # self.assertEqual(e[libuser.EMAIL], ['user6_2@example.com'])

    def testUserAdd3(self):
        # Large IDs.
        e = self.a.initUser('user6_3')
        e[libuser.UIDNUMBER] = LARGE_ID + 630
        e[libuser.GIDNUMBER] = LARGE_ID + 631
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_3')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user6_3'])
        self.assertEqual(e[libuser.UIDNUMBER], [LARGE_ID + 630])
        self.assertEqual(e[libuser.GIDNUMBER], [LARGE_ID + 631])

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
        # A maximal case, including renaming
        e = self.a.initUser('user7_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_2')
        self.assertNotEqual(e[libuser.USERNAME], ['user7_2username'])
        e[libuser.USERNAME] = 'user7_2username'
        self.assertNotEqual(e[libuser.USERPASSWORD], ['!!pwuser7_2'])
        e[libuser.USERPASSWORD] = '!!pwuser7_2'
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
        self.assertNotEqual(e[libuser.SHADOWPASSWORD], ['!!user7_2'])
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
        self.assertEqual(e[libuser.USERPASSWORD], ['!!pwuser7_2'])
        self.assertEqual(e[libuser.UIDNUMBER], [4237])
        self.assertEqual(e[libuser.GIDNUMBER], [3742])
        self.assertEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/user7_2home'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser7_2'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!user7_2'])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [12681])
        self.assertEqual(e[libuser.SHADOWMIN], [5])
        self.assertEqual(e[libuser.SHADOWMAX], [98765])
        self.assertEqual(e[libuser.SHADOWWARNING], [10])
        self.assertEqual(e[libuser.SHADOWINACTIVE], [8])
        self.assertEqual(e[libuser.SHADOWEXPIRE], [9])
        self.assertEqual(e[libuser.SHADOWFLAG], [255])

    def testUserMod3(self):
        # Large IDs
        e = self.a.initUser('user7_3')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_3')
        self.assertNotEqual(e[libuser.UIDNUMBER], [LARGE_ID + 730])
        e[libuser.UIDNUMBER] = LARGE_ID + 730
        self.assertNotEqual(e[libuser.GIDNUMBER], [LARGE_ID + 731])
        e[libuser.GIDNUMBER] = LARGE_ID + 731
        self.a.modifyUser(e, False)
        del e
        e = self.a.lookupUserByName('user7_3')
        self.assert_(e)
        self.assertEqual(e[libuser.UIDNUMBER], [LARGE_ID + 730])
        self.assertEqual(e[libuser.GIDNUMBER], [LARGE_ID + 731])

    def testUserMod4(self):
        # Some of the attributes are not present
        e = self.a.initUser('user7_4')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_4')
        e.clear(libuser.SHADOWFLAG)
        e.clear(libuser.SHADOWMAX)
        self.a.modifyUser(e, False)
        del e
        e = self.a.lookupUserByName('user7_4')
        self.assert_(e)
        self.assertEqual(e[libuser.SHADOWMAX], [99999])
        self.assertEqual(e[libuser.SHADOWFLAG], [-1])

    def testUserDel(self):
        e = self.a.initUser('user8_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user8_1')
        self.assert_(e)
        self.a.deleteUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user8_1')
        self.assertEqual(e, None)

    def testUserLock1(self):
        e = self.a.initUser('user9_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user9_1')
        self.a.setpassUser(e, '00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])
        self.a.lockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!00as1wm0AZG56'])

    def testUserLock2(self):
        e = self.a.initUser('user9_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user9_2')
        self.a.setpassUser(e, '!!00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!00as1wm0AZG56'])
        self.a.lockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!00as1wm0AZG56'])

    def testUserUnlock1(self):
        e = self.a.initUser('user10_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_1')
        self.a.setpassUser(e, '!!00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!00as1wm0AZG56'])
        self.a.unlockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])

    def testUserUnlock2(self):
        e = self.a.initUser('user10_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_2')
        self.a.setpassUser(e, '00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])
        self.a.unlockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])

    def testUserUnlock3(self):
        e = self.a.initUser('user10_3')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_3')
        self.a.setpassUser(e, '!!', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])
        self.a.unlockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [''])

    def testUserUnlockNonempty1(self):
        e = self.a.initUser('user32_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_1')
        self.a.setpassUser(e, '!!00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!00as1wm0AZG56'])
        self.a.unlockUser(e, True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])

    def testUserUnlockNonempty2(self):
        e = self.a.initUser('user32_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_2')
        self.a.setpassUser(e, '00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])
        self.a.unlockUser(e, True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['00as1wm0AZG56'])

    def testUserUnlockNonempty3(self):
        e = self.a.initUser('user32_3')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_3')
        self.a.setpassUser(e, '!!', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])
        self.assertRaises(RuntimeError, self.a.unlockUser, e, True)
        del e
        e = self.a.lookupUserByName('user32_3')
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])

    def testUserIslocked1(self):
        e = self.a.initUser('user11_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user11_1')
        self.a.setpassUser(e, '!!01aK1FxKE9YVU', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!01aK1FxKE9YVU'])
        self.assertEqual(self.a.userIsLocked(e), 1)

    def testUserIslocked2(self):
        e = self.a.initUser('user11_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user11_2')
        self.a.setpassUser(e, '01aK1FxKE9YVU', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['01aK1FxKE9YVU'])
        self.assertEqual(self.a.userIsLocked(e), 0)

    def testUserSetpass1(self):
        e = self.a.initUser('user12_1')
        e[libuser.SHADOWPASSWORD] = '02oawyZdjhhpg'
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user12_1')
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['02oawyZdjhhpg'])
        self.a.setpassUser(e, 'password', False)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        crypted = crypt.crypt('password', e[libuser.SHADOWPASSWORD][0][:11])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [crypted])

    def testUserSetpass2(self):
        # Forcing the non-shadow password to 'x'
        e = self.a.initUser('user12_2')
        e[libuser.USERPASSWORD] = '*'
        e[libuser.SHADOWPASSWORD] = '08lnuxCM.c36E'
        self.a.addUser(e, False, False)
        del e
        # shadow module's addUser forces USERPASSWORD to 'x'
        e = self.a.lookupUserByName('user12_2')
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['08lnuxCM.c36E'])
        e[libuser.USERPASSWORD] = '*'
        self.a.modifyUser(e, False)
        del e
        e = self.a.lookupUserByName('user12_2')
        self.assertEqual(e[libuser.USERPASSWORD], ['*'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['08lnuxCM.c36E'])
        self.a.setpassUser(e, 'password', False)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        crypted = crypt.crypt('password', e[libuser.SHADOWPASSWORD][0][:11])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [crypted])

    def testUserSetpass3(self):
        # Overriding an invalid encrypted password
        e = self.a.lookupUserByName('user12_3')
        self.assertEqual(e[libuser.USERPASSWORD], ['*'])
        self.assertRaises(KeyError, lambda: e[libuser.SHADOWPASSWORD])
        self.a.setpassUser(e, 'password', False)
        crypted = crypt.crypt('password', e[libuser.USERPASSWORD][0][:11])
        self.assertEqual(e[libuser.USERPASSWORD], [crypted])
        self.assertRaises(KeyError, lambda: e[libuser.SHADOWPASSWORD])

    def testUserRemovepass(self):
        e = self.a.initUser('user13_1')
        e[libuser.SHADOWPASSWORD] = '03dgZm5nZvqOc'
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user13_1')
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['03dgZm5nZvqOc'])
        self.a.removepassUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [''])

    def testUsersEnumerate1(self):
        e = self.a.initUser('user14_1')
        self.a.addUser(e, False, False)
        e = self.a.initUser('user14_2')
        self.a.addUser(e, False, False)
        v = self.a.enumerateUsers('user14*')
        v.sort()
        self.assertEqual(v, ['user14_1', 'user14_2'])

    def testUsersEnumerate2(self):
        v = [name for name in self.a.enumerateUsers('*')
             if name.startswith('-') or name.startswith('+')]
        self.assertEqual(v, [])

    def testUsersEnumerateByGroup1(self):
        gid = 1501 # Hopefully unique
        e = self.a.initGroup('group15_1')
        e[libuser.GIDNUMBER] = gid
        e[libuser.MEMBERNAME] = 'user15_2'
        self.a.addGroup(e)
        e = self.a.initUser('user15_1')
        e[libuser.GIDNUMBER] = gid
        self.a.addUser(e, False, False)
        e = self.a.initUser('user15_2')
        e[libuser.GIDNUMBER] = gid + 10
        self.a.addUser(e, False, False)
        v = self.a.enumerateUsersByGroup('group15_1')
        v.sort()
        self.assertEqual(v, ['user15_1', 'user15_2'])

    def testUsersEnumerateByGroup2(self):
        gid = 1502 # Hopefully unique
        e = self.a.initGroup('group15_2')
        e[libuser.GIDNUMBER] = gid
        self.a.addGroup(e)
        e = self.a.initUser('user15_3')
        e[libuser.GIDNUMBER] = gid
        self.a.addUser(e, False, False)
        self.assertEqual(self.a.enumerateUsersByGroup('group15_2'),
                         ['user15_3'])

    def testUsersEnumerateByGroup3(self):
        gid = 1503 # Hopefully unique
        e = self.a.initGroup('group15_3')
        e[libuser.GIDNUMBER] = gid
        e[libuser.MEMBERNAME] = 'user15_4'
        self.a.addGroup(e)
        e = self.a.initUser('user15_4')
        e[libuser.GIDNUMBER] = gid + 10
        self.a.addUser(e, False, False)
        self.assertEqual(self.a.enumerateUsersByGroup('group15_3'),
                         ['user15_4'])

    def testUsersEnumerateByGroup4(self):
        # Data set up in files_test
        self.assertEqual(self.a.enumerateUsersByGroup('group15_4'), [])

    def testUsersEnumerateFull1(self):
        e = self.a.initUser('user16_1')
        self.a.addUser(e, False, False)
        e = self.a.initUser('user16_2')
        self.a.addUser(e, False, False)
        v = [x[libuser.USERNAME] for x in self.a.enumerateUsersFull('user16*')]
        v.sort()
        self.assertEqual(v, [['user16_1'], ['user16_2']])

    def testUsersEnumerateFull2(self):
        v = [x[libuser.USERNAME] for x in self.a.enumerateUsersFull('*')]
        v = [name for (name,) in v
             if name.startswith('-') or name.startswith('+')]
        self.assertEqual(v, [])

    def testUsersEnumerateFull3(self):
        # Only the user name is matched
        e = self.a.initUser('user16_3')
        self.a.addUser(e, False, False)
        self.assertEqual(self.a.enumerateUsersFull('user16_3:*'), [])

    def testGroupLookupName1(self):
        e = self.a.initGroup('group17_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group17_1')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group17_1'])
        del e
        e = self.a.lookupGroupByName('group17_does_not_exist')
        self.assertEqual(e, None)

    def testGroupLookupName2(self):
        # Handling of empty/default values
        e = self.a.lookupGroupByName('empty_group')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['empty_group'])
        self.assertEqual(e[libuser.GROUPPASSWORD], [''])
        self.assertEqual(e[libuser.GIDNUMBER], [44])
        self.assertRaises(KeyError, lambda: e[libuser.MEMBERNAME])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [''])
        self.assertRaises(KeyError, lambda: e[libuser.ADMINISTRATORNAME])

    def testGroupLookupName3(self):
        # Handling of values that appear to be numbers
        e = self.a.lookupGroupByName('077')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['077'])
        self.assertEqual(e[libuser.GROUPPASSWORD], ['077'])
        self.assertEqual(e[libuser.GIDNUMBER], [1730])
        self.assertEqual(e[libuser.MEMBERNAME], ['077'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['077'])
        self.assertEqual(e[libuser.ADMINISTRATORNAME], ['077'])

    def testGroupLookupId(self):
        e = self.a.initGroup('group18_1')
        self.a.addGroup(e)
        gid = e[libuser.GIDNUMBER][0]
        del e
        e = self.a.lookupGroupById(gid)
        self.assert_(e)
        self.assertEqual(e[libuser.GIDNUMBER], [gid])
        del e
        e = self.a.lookupGroupById(999999)
        self.assertEqual(e, None)
        del e
        e = self.a.lookupGroupById(LARGE_ID + 1810)
        self.assertEqual(e, None)

    def testGroupDefault(self):
        # Test the default/LU_GROUPNAME = %n preserves groupnames that appear
        # to be numbers
        e = self.a.initGroup('077')
        self.assertEqual(e[libuser.GROUPNAME], ['077'])

    # testGroupAddPrep
    # Setting of GROUPPASSWORD to "x" tested below

    def testGroupAdd1(self):
        # A minimal case
        e = self.a.initGroup('group21_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group21_1')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group21_1'])
        # Default values
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])

    def testGroupAdd2(self):
        # A maximal case
        e = self.a.initGroup('group21_2')
        e[libuser.GROUPNAME] = 'group21_2groupname'
        e[libuser.GROUPPASSWORD] = '!!badgroup21_2' # Should be ignored
        e[libuser.GIDNUMBER] = 4237
        e[libuser.MEMBERNAME] = ['group21_2member1', 'group21_2member2']
        e[libuser.SHADOWPASSWORD] = '!!group21_2'
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group21_2groupname')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group21_2groupname'])
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.GIDNUMBER], [4237])
        v = e[libuser.MEMBERNAME]
        v.sort()
        self.assertEqual(v, ['group21_2member1', 'group21_2member2'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!group21_2'])

    def testGroupAdd3(self):
        # Large IDs
        e = self.a.initGroup('group21_3')
        e[libuser.GIDNUMBER] = LARGE_ID + 2130
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group21_3')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group21_3'])
        self.assertEqual(e[libuser.GIDNUMBER], [LARGE_ID + 2130])

    def testGroupMod1(self):
        # A minimal case
        e = self.a.initGroup('group22_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_1')
        self.assertRaises(KeyError, lambda x: x[libuser.MEMBERNAME], e)
        e[libuser.MEMBERNAME] = 'group22_1member'
        self.a.modifyGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_1')
        self.assertEqual(e[libuser.MEMBERNAME], ['group22_1member'])

    def testGroupMod2(self):
        # A maximal case, including renaming
        e = self.a.initGroup('group22_2')
        e[libuser.MEMBERNAME] = ['group22_2member1', 'group22_2member2']
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_2')
        self.assertNotEqual(e[libuser.GROUPNAME], ['group22_2groupname'])
        e[libuser.GROUPNAME] = 'group22_2groupname'
        self.assertNotEqual(e[libuser.GROUPPASSWORD], ['!!grgroup22_2'])
        e[libuser.GROUPPASSWORD] = '!!grgroup22_2'
        self.assertNotEqual(e[libuser.GIDNUMBER], [4237])
        e[libuser.GIDNUMBER] = 4237
        v = e[libuser.MEMBERNAME]
        v.sort()
        self.assertNotEqual(v, ['group22_2member1', 'group22_2member3'])
        e[libuser.MEMBERNAME] = ['group22_2member1', 'group22_2member3']
        self.assertNotEqual(e[libuser.SHADOWPASSWORD], ['!!group22_2'])
        e[libuser.SHADOWPASSWORD] = '!!group22_2'
        self.a.modifyGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_2')
        self.assertEqual(e, None)
        del e
        e = self.a.lookupGroupByName('group22_2groupname')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group22_2groupname'])
        self.assertEqual(e[libuser.GROUPPASSWORD], ['!!grgroup22_2'])
        self.assertEqual(e[libuser.GIDNUMBER], [4237])
        v = e[libuser.MEMBERNAME]
        v.sort()
        self.assertEqual(v, ['group22_2member1', 'group22_2member3'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!group22_2'])

    def testGroupMod3(self):
        # Large IDs
        e = self.a.initGroup('group22_3')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_3')
        self.assertNotEqual(e[libuser.GIDNUMBER], [LARGE_ID + 2230])
        e[libuser.GIDNUMBER] = LARGE_ID + 2230
        self.a.modifyGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_3')
        self.assert_(e)
        self.assertEqual(e[libuser.GIDNUMBER], [LARGE_ID + 2230])

    def testGroupDel(self):
        e = self.a.initGroup('group23_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group23_1')
        self.assert_(e)
        self.a.deleteGroup(e)
        del e
        e = self.a.lookupGroupByName('group23_1')
        self.assertEqual(e, None)

    def testGroupLock1(self):
        e = self.a.initGroup('group24_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group24_1')
        self.a.setpassGroup(e, '04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])
        self.a.lockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!04cmES7HM6wtg'])

    def testGroupLock2(self):
        e = self.a.initGroup('group24_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group24_2')
        self.a.setpassGroup(e, '!!04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!04cmES7HM6wtg'])
        self.a.lockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!04cmES7HM6wtg'])

    def testGroupUnlock1(self):
        e = self.a.initGroup('group25_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_1')
        self.a.setpassGroup(e, '!!04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!04cmES7HM6wtg'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])

    def testGroupUnlock2(self):
        e = self.a.initGroup('group25_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_2')
        self.a.setpassGroup(e, '04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])

    def testGroupUnlock3(self):
        e = self.a.initGroup('group25_3')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_3')
        self.a.setpassGroup(e, '!!', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [''])

    def testGroupUnlockNonempty1(self):
        e = self.a.initGroup('group33_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_1')
        self.a.setpassGroup(e, '!!04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!04cmES7HM6wtg'])
        self.a.unlockGroup(e, True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])

    def testGroupUnlockNonempty2(self):
        e = self.a.initGroup('group33_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_2')
        self.a.setpassGroup(e, '04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['04cmES7HM6wtg'])

    def testGroupUnlockNonempty3(self):
        e = self.a.initGroup('group33_3')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_3')
        self.a.setpassGroup(e, '!!', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])
        self.assertRaises(RuntimeError, self.a.unlockGroup, e, True)
        del e
        e = self.a.lookupGroupByName('group33_3')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!'])

    def testGroupIsLocked1(self):
        e = self.a.initGroup('group26_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group26_1')
        self.a.setpassGroup(e, '!!05/lfLEyErrp2', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['!!05/lfLEyErrp2'])
        self.assertEqual(self.a.groupIsLocked(e), 1)
        
    def testGroupIsLocked2(self):
        e = self.a.initGroup('group26_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group26_2')
        self.a.setpassGroup(e, '05/lfLEyErrp2', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['05/lfLEyErrp2'])
        self.assertEqual(self.a.groupIsLocked(e), 0)

    def testGroupSetpass1(self):
        e = self.a.initGroup('group27_1')
        e[libuser.SHADOWPASSWORD] = '06aZrb3pzuu/6'
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group27_1')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['06aZrb3pzuu/6'])
        self.a.setpassGroup(e, 'password', False)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        crypted = crypt.crypt('password', e[libuser.SHADOWPASSWORD][0][:11])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [crypted])

    def testGroupSetpass2(self):
        # Forcing the non-shadow password to 'x'
        e = self.a.initGroup('group27_2')
        e[libuser.GROUPPASSWORD] = '*'
        e[libuser.SHADOWPASSWORD] = '07ZZy2Pihe/gg'
        self.a.addGroup(e)
        del e
        # shadow module's addGroup forces GROUPPASSWORD to 'x'
        e = self.a.lookupGroupByName('group27_2')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['07ZZy2Pihe/gg'])
        e[libuser.GROUPPASSWORD] = '*'
        self.a.modifyGroup(e)
        del e
        e = self.a.lookupGroupByName('group27_2')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['*'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['07ZZy2Pihe/gg'])
        self.a.setpassGroup(e, 'password', False)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        crypted = crypt.crypt('password', e[libuser.SHADOWPASSWORD][0][:11])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [crypted])

    def testGroupSetpass3(self):
        # Overriding an invalid encrypted password
        e = self.a.lookupGroupByName('group27_3')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['*'])
        self.assertRaises(KeyError, lambda: e[libuser.SHADOWPASSWORD])
        self.a.setpassGroup(e, 'password', False)
        crypted = crypt.crypt('password', e[libuser.GROUPPASSWORD][0][:11])
        self.assertEqual(e[libuser.GROUPPASSWORD], [crypted])
        self.assertRaises(KeyError, lambda: e[libuser.SHADOWPASSWORD])

    def testGroupRemovepass(self):
        e = self.a.initGroup('group28_1')
        e[libuser.SHADOWPASSWORD] = '07Js7N.eEhbgs'
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group28_1')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], ['07Js7N.eEhbgs'])
        self.a.removepassGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['x'])
        self.assertEqual(e[libuser.SHADOWPASSWORD], [''])

    def testGroupsEnumerate1(self):
        e = self.a.initGroup('group29_1')
        self.a.addGroup(e)
        e = self.a.initGroup('group29_2')
        self.a.addGroup(e)
        v = self.a.enumerateGroups('group29*')
        v.sort()
        self.assertEqual(v, ['group29_1', 'group29_2'])

    def testGroupsEnumerate2(self):
        v = [name for name in self.a.enumerateGroups('*')
             if name.startswith('-') or name.startswith('+')]
        self.assertEqual(v, [])

    def testGroupsEnumerateByUser1(self):
        gid = 3001 # Hopefully unique
        e = self.a.initUser('user30_1')
        e[libuser.GIDNUMBER] = gid
        self.a.addUser(e, False, False)
        e = self.a.initGroup('group30_1')
        e[libuser.GIDNUMBER] = gid
        self.a.addGroup(e)
        e = self.a.initGroup('group30_2')
        e[libuser.GIDNUMBER] = gid + 10
        e[libuser.MEMBERNAME] = 'user30_1'
        self.a.addGroup(e)
        v = self.a.enumerateGroupsByUser('user30_1')
        v.sort()
        self.assertEqual(v, ['group30_1', 'group30_2'])

    def testGroupsEnumerateByUser2(self):
        gid = 3002 # Hopefully unique
        e = self.a.initUser('user30_2')
        e[libuser.GIDNUMBER] = gid
        self.a.addUser(e, False, False)
        e = self.a.initGroup('group30_3')
        e[libuser.GIDNUMBER] = gid
        self.a.addGroup(e)
        self.assertEqual(self.a.enumerateGroupsByUser('user30_2'),
                         ['group30_3'])

    def testGroupsEnumerateByUser3(self):
        gid = 3003 # Hopefully unique
        e = self.a.initUser('user30_3')
        e[libuser.GIDNUMBER] = gid
        self.a.addUser(e, False, False)
        e = self.a.initGroup('group30_4')
        e[libuser.GIDNUMBER] = gid + 10
        e[libuser.MEMBERNAME] = 'user30_3'
        self.a.addGroup(e)
        self.assertEqual(self.a.enumerateGroupsByUser('user30_3'),
                         ['group30_4'])

    def testGroupsEnumerateByUser4(self):
        # Data set up in files_test
        self.assertEqual(self.a.enumerateGroupsByUser('user30_4'), [])

    def testGroupsEnumerateFull1(self):
        e = self.a.initGroup('group31_1')
        self.a.addGroup(e)
        e = self.a.initGroup('group31_2')
        self.a.addGroup(e)
        v = [x[libuser.GROUPNAME]
             for x in self.a.enumerateGroupsFull('group31*')]
        v.sort()
        self.assertEqual(v, [['group31_1'], ['group31_2']])

    def testGroupsEnumerateFull2(self):
        v = [x[libuser.GROUPNAME] for x in self.a.enumerateGroupsFull('*')]
        v = [name for (name,) in v
             if name.startswith('-') or name.startswith('+')]
        self.assertEqual(v, [])

    def testGroupsEnumerateFull3(self):
        # Only the user name is matched
        e = self.a.initGroup('group31_3')
        self.a.addGroup(e)
        self.assertEqual(self.a.enumerateGroupsFull('group31_3:*'), [])

    def tearDown(self):
        del self.a


if __name__ == '__main__':
    unittest.main()
