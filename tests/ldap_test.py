import crypt
import libuser
import unittest

LARGE_ID = 2147483648

def prompt_callback(prompts):
    for p in prompts:
        if p.key == 'ldap/password':
            p.value = 'password'
        else:
            p.value = p.default_value

# This is ugly; ideally we would want a separate connection for each test case,
# but libssl REALLY doesn't like being unloaded (libcrypto is not unloaded
# and keeps pointers to unloaded libssl)
admin = libuser.admin(prompt = prompt_callback)

# Test case order matches the order of function pointers in struct lu_module
class Tests(unittest.TestCase):
    def setUp(self):
        # See the comment at the libuser.admin() call above
        self.a = admin

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
        del e
        e = self.a.lookupUserById(LARGE_ID + 310)
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
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!!'])

    def testUserAdd2(self):
        # A maximal case
        e = self.a.initUser('user6_2')
        e[libuser.USERNAME] = 'user6_2username'
        e[libuser.USERPASSWORD] = '!!user6_2'
        e[libuser.UIDNUMBER] = 4237
        e[libuser.GIDNUMBER] = 3742
        e[libuser.GECOS] = 'Full Name,Office,1234,4321'
        e[libuser.HOMEDIRECTORY] = '/home/user6_2home'
        e[libuser.LOGINSHELL] = '/sbin/nologinuser6_2'
        e[libuser.SHADOWPASSWORD] = '!!baduser6_2' # Should be ignored
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
        e[libuser.ROOMNUMBER] = '404'
        e[libuser.TELEPHONENUMBER] = '1234'
        e[libuser.HOMEPHONE] = '4321'
        e[libuser.EMAIL] = 'user6_2@example.com'
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_2username')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user6_2username'])
        self.assertEqual(e[libuser.USERPASSWORD], ['!!user6_2'])
        self.assertEqual(e[libuser.UIDNUMBER], [4237])
        self.assertEqual(e[libuser.GIDNUMBER], [3742])
        self.assertEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/user6_2home'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser6_2'])
        self.assertRaises(KeyError, lambda x: x[libuser.SHADOWPASSWORD], e)
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
        self.assertEqual(e[libuser.ROOMNUMBER], ['404'])
        self.assertEqual(e[libuser.TELEPHONENUMBER], ['1234'])
        self.assertEqual(e[libuser.HOMEPHONE], ['4321'])
        # Not stored by our LDAP module
        # self.assertEqual(e[libuser.EMAIL], ['user6_2@example.com'])

    def testUserAdd3(self):
        # Schema violation
        e = self.a.initUser('user6_3')
        e[libuser.GIVENNAME] = 'Given'
        # e[libuser.SN] required by inetOrgPerson schema, but not provided
        self.assertRaises(RuntimeError, self.a.addUser, e, False, False)

    def testUserAdd4(self):
        # Large IDs.
        e = self.a.initUser('user6_4')
        e[libuser.UIDNUMBER] = LARGE_ID + 640
        e[libuser.GIDNUMBER] = LARGE_ID + 641
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_4')
        self.assert_(e)
        self.assertEqual(e[libuser.USERNAME], ['user6_4'])
        self.assertEqual(e[libuser.UIDNUMBER], [LARGE_ID + 640])
        self.assertEqual(e[libuser.GIDNUMBER], [LARGE_ID + 641])

    def testUserAdd5(self):
        # Let the user specify dangerous/dubious home directory paths explicitly
        for name in ('.', '..'):
            e = self.a.initUser(name)
            e[libuser.HOMEDIRECTORY] = '/home/' + name
            self.a.addUser(e, False, False)
            del e
            e = self.a.lookupUserByName(name)
            self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/' + name])
            self.a.deleteUser(e, False, False)
        e = self.a.initUser('user6_5')
        e[libuser.HOMEDIRECTORY] = '/home/..'
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user6_5')
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/..'])
        # ... but nevere create such home directory paths by default
        for name in ('.', '..'):
            e = self.a.initUser(name)
            self.assertRaises(RuntimeError, self.a.addUser, e, False, False)

    def testUserAdd6(self):
        # Adding duplicate entries
        e = self.a.initUser('user6_6')
        self.a.addUser(e, False, False)
        del e
        e = self.a.initUser('user6_6')
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
        # A maximal case, including renaming
        e = self.a.initUser('user7_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_2')
        self.assertNotEqual(e[libuser.USERNAME], ['user7_2username'])
        e[libuser.USERNAME] = 'user7_2username'
        self.assertNotEqual(e[libuser.USERPASSWORD], ['!!user7_2'])
        e[libuser.USERPASSWORD] = '!!user7_2'
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
        self.assertEqual(e[libuser.USERPASSWORD], ['!!user7_2'])
        self.assertEqual(e[libuser.UIDNUMBER], [4237])
        self.assertEqual(e[libuser.GIDNUMBER], [3742])
        self.assertEqual(e[libuser.GECOS], ['Full Name,Office,1234,4321'])
        self.assertEqual(e[libuser.HOMEDIRECTORY], ['/home/user7_2home'])
        self.assertEqual(e[libuser.LOGINSHELL], ['/sbin/nologinuser7_2'])
        self.assertRaises(KeyError, lambda x: x[libuser.SHADOWPASSWORD], e)
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
        # No modification at all
        e = self.a.initUser('user7_4')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_4')
        self.a.modifyUser(e, False)
        del e
        e = self.a.lookupUserByName('user7_4')
        self.assert_(e)

    def testUserMod5(self):
        # Renaming to create duplicate entries
        e = self.a.initUser('user7_5')
        self.a.addUser(e, False, False)
        del e
        e = self.a.initUser('user7_6')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user7_6')
        e[libuser.USERNAME] = 'user7_5'
        self.assertRaises(RuntimeError, self.a.modifyUser, e, False)

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
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])
        self.a.lockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!00as1wm0AZG56'])

    def testUserLock2(self):
        e = self.a.initUser('user9_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user9_2')
        self.a.setpassUser(e, '!00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!00as1wm0AZG56'])
        self.a.lockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!00as1wm0AZG56'])

    def testUserLock3(self):
        e = self.a.initUser('user9_3')
        e[libuser.USERPASSWORD] = '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user9_3')
        self.assertEqual(e[libuser.USERPASSWORD],
                         ['{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='])
        self.assertRaises(RuntimeError, self.a.lockUser, e)

    def testUserUnlock1(self):
        e = self.a.initUser('user10_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_1')
        self.a.setpassUser(e, '!00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!00as1wm0AZG56'])
        self.a.unlockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])

    def testUserUnlock2(self):
        e = self.a.initUser('user10_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_2')
        self.a.setpassUser(e, '00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])
        self.a.unlockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])

    def testUserUnlock3(self):
        e = self.a.initUser('user10_3')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_3')
        self.a.setpassUser(e, '!', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!'])
        self.a.unlockUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}'])

    def testUserUnlock4(self):
        e = self.a.initUser('user10_4')
        e[libuser.USERPASSWORD] = '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user10_4')
        self.assertEqual(e[libuser.USERPASSWORD],
                         ['{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='])
        self.assertRaises(RuntimeError, self.a.unlockUser, e)

    def testUserUnlockNonempty1(self):
        e = self.a.initUser('user32_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_1')
        self.a.setpassUser(e, '!00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!00as1wm0AZG56'])
        self.a.unlockUser(e, True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])

    def testUserUnlockNonempty2(self):
        e = self.a.initUser('user32_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_2')
        self.a.setpassUser(e, '00as1wm0AZG56', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])
        self.a.unlockUser(e, True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}00as1wm0AZG56'])

    def testUserUnlockNonempty3(self):
        e = self.a.initUser('user32_3')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_3')
        self.a.setpassUser(e, '!', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!'])
        self.assertRaises(RuntimeError, self.a.unlockUser, e, True)
        del e
        e = self.a.lookupUserByName('user32_3')
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!'])

    def testUserUnlockNonempty4(self):
        e = self.a.initUser('user32_4')
        e[libuser.USERPASSWORD] = '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user32_4')
        self.assertEqual(e[libuser.USERPASSWORD],
                         ['{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='])
        self.assertRaises(RuntimeError, self.a.unlockUser, e, True)

    def testUserIslocked1(self):
        e = self.a.initUser('user11_1')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user11_1')
        self.a.setpassUser(e, '!01aK1FxKE9YVU', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}!01aK1FxKE9YVU'])
        self.assertEqual(self.a.userIsLocked(e), 1)

    def testUserIslocked2(self):
        e = self.a.initUser('user11_2')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user11_2')
        self.a.setpassUser(e, '01aK1FxKE9YVU', True)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}01aK1FxKE9YVU'])
        self.assertEqual(self.a.userIsLocked(e), 0)

    def testUserSetpass1(self):
        e = self.a.initUser('user12_1')
        e[libuser.USERPASSWORD] = '{CRYPT}02oawyZdjhhpg'
        e[libuser.SHADOWLASTCHANGE] = 100
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user12_1')
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}02oawyZdjhhpg'])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [100])
        self.a.setpassUser(e, 'password', False)
        del e
        e = self.a.lookupUserByName('user12_1')
        crypted = crypt.crypt('password', e[libuser.USERPASSWORD][0][7:])
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}' + crypted])
        self.assert_(e[libuser.SHADOWLASTCHANGE][0] > 10000)


    def testUserSetpass2(self):
        e = self.a.initUser('user12_2')
        e[libuser.USERPASSWORD] = ['unknown', '{CRYPT}02oawyZdjhhpg']
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user12_2')
        v = e[libuser.USERPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown', '{CRYPT}02oawyZdjhhpg'])
        self.a.setpassUser(e, 'password', False)
        v = e[libuser.USERPASSWORD]
        v.sort()
        crypted = crypt.crypt('password', v[1][7:])
        self.assertEqual(v, ['unknown', '{CRYPT}' + crypted])

    def testUserSetpass3(self):
        e = self.a.initUser('user12_3')
        e[libuser.USERPASSWORD] = ['unknown1', 'unknown2']
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user12_3')
        v = e[libuser.USERPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown1', 'unknown2'])
        self.a.setpassUser(e, 'password', False)
        crypted = crypt.crypt('password', e[libuser.USERPASSWORD][0][7:])
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}' + crypted])

    def testUserRemovepass1(self):
        e = self.a.initUser('user13_1')
        e[libuser.USERPASSWORD] = '{CRYPT}03dgZm5nZvqOc'
        e[libuser.SHADOWLASTCHANGE] = 100
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user13_1')
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}03dgZm5nZvqOc'])
        self.assertEqual(e[libuser.SHADOWLASTCHANGE], [100])
        self.a.removepassUser(e)
        del e
        e = self.a.lookupUserByName('user13_1')
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}'])
        self.assert_(e[libuser.SHADOWLASTCHANGE][0] > 10000)

    def testUserRemovepass2(self):
        e = self.a.initUser('user13_2')
        e[libuser.USERPASSWORD] = ['unknown', '{CRYPT}03dgZm5nZvqOc']
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user13_2')
        v = e[libuser.USERPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown', '{CRYPT}03dgZm5nZvqOc'])
        self.a.removepassUser(e)
        v = e[libuser.USERPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown', '{CRYPT}'])

    def testUserRemovepass3(self):
        e = self.a.initUser('user13_3')
        e[libuser.USERPASSWORD] = ['unknown1', 'unknown2']
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user13_3')
        v = e[libuser.USERPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown1', 'unknown2'])
        self.a.removepassUser(e)
        self.assertEqual(e[libuser.USERPASSWORD], ['{CRYPT}'])

    def testUsersEnumerate(self):
        e = self.a.initUser('user14_1')
        self.a.addUser(e, False, False)
        e = self.a.initUser('user14_2')
        self.a.addUser(e, False, False)
        v = self.a.enumerateUsers('user14*')
        v.sort()
        self.assertEqual(v, ['user14_1', 'user14_2'])

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
        v = self.a.enumerateUsersByGroup('group15_3')
        self.assertEqual(self.a.enumerateUsersByGroup('group15_3'),
                         ['user15_4'])

    def testUsersEnumerateFull(self):
        e = self.a.initUser('user16_1')
        self.a.addUser(e, False, False)
        e = self.a.initUser('user16_2')
        self.a.addUser(e, False, False)
        v = map(lambda x: x[libuser.USERNAME],
                self.a.enumerateUsersFull('user16*'))
        v.sort()
        self.assertEqual(v, [['user16_1'], ['user16_2']])

    def testGroupLookupName(self):
        e = self.a.initGroup('group17_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group17_1')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group17_1'])
        del e
        e = self.a.lookupGroupByName('group17_does_not_exist')
        self.assertEqual(e, None)

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

    # testGroupDefault
    # There is little to test, in addition most is configurable

    # testGroupAddPrep
    # Nothing to test

    def testGroupAdd1(self):
        # A minimal case
        e = self.a.initGroup('group21_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group21_1')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group21_1'])
        self.assertRaises(KeyError, lambda x: x[libuser.GROUPPASSWORD], e)

    def testGroupAdd2(self):
        # A maximal case
        e = self.a.initGroup('group21_2')
        e[libuser.GROUPNAME] = 'group21_2groupname'
        e[libuser.GROUPPASSWORD] = '!!group21_2'
        e[libuser.GIDNUMBER] = 4237
        e[libuser.MEMBERNAME] = ['group21_2member1', 'group21_2member2']
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group21_2groupname')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group21_2groupname'])
        self.assertEqual(e[libuser.GROUPPASSWORD], ['!!group21_2'])
        self.assertEqual(e[libuser.GIDNUMBER], [4237])
        v = e[libuser.MEMBERNAME]
        v.sort()
        self.assertEqual(v, ['group21_2member1', 'group21_2member2'])

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

    def testGroupAdd4(self):
        # Adding duplicate entries
        e = self.a.initGroup('group21_4')
        self.a.addGroup(e)
        del e
        e = self.a.initGroup('group21_4')
        self.assertRaises(RuntimeError, self.a.addGroup, e)

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
        self.assertNotEqual(e[libuser.GIDNUMBER], [4237])
        e[libuser.GIDNUMBER] = 4237
        v = e[libuser.MEMBERNAME]
        v.sort()
        self.assertNotEqual(v, ['group22_2member1', 'group22_2member3'])
        e[libuser.MEMBERNAME] = ['group22_2member1', 'group22_2member3']
        self.a.modifyGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_2')
        self.assertEqual(e, None)
        del e
        e = self.a.lookupGroupByName('group22_2groupname')
        self.assert_(e)
        self.assertEqual(e[libuser.GROUPNAME], ['group22_2groupname'])
        self.assertEqual(e[libuser.GIDNUMBER], [4237])
        v = e[libuser.MEMBERNAME]
        v.sort()
        self.assertEqual(v, ['group22_2member1', 'group22_2member3'])

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

    def testGroupMod4(self):
        # Renaming to create duplicate entries
        e = self.a.initGroup('group22_4')
        self.a.addGroup(e)
        del e
        e = self.a.initGroup('group22_5')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group22_5')
        e[libuser.GROUPNAME] = 'group22_4'
        self.assertRaises(RuntimeError, self.a.modifyGroup, e)

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
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])
        self.a.lockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!04cmES7HM6wtg'])

    def testGroupLock2(self):
        e = self.a.initGroup('group24_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group24_2')
        self.a.setpassGroup(e, '!04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!04cmES7HM6wtg'])
        self.a.lockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!04cmES7HM6wtg'])

    def testGroupLock3(self):
        e = self.a.initGroup('group24_3')
        e[libuser.USERPASSWORD] = '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group24_3')
        self.assertEqual(e[libuser.GROUPPASSWORD],
                         ['{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='])
        self.assertRaises(RuntimeError, self.a.lockGroup, e)

    def testGroupUnlock1(self):
        e = self.a.initGroup('group25_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_1')
        self.a.setpassGroup(e, '!04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!04cmES7HM6wtg'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])

    def testGroupUnlock2(self):
        e = self.a.initGroup('group25_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_2')
        self.a.setpassGroup(e, '04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])

    def testGroupUnlock3(self):
        e = self.a.initGroup('group25_3')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_3')
        self.a.setpassGroup(e, '!', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!'])
        self.a.unlockGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}'])

    def testGroupUnlock4(self):
        e = self.a.initGroup('group25_4')
        e[libuser.USERPASSWORD] = '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group25_4')
        self.assertEqual(e[libuser.GROUPPASSWORD],
                         ['{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='])
        self.assertRaises(RuntimeError, self.a.unlockGroup, e)

    def testGroupUnlockNonempty1(self):
        e = self.a.initGroup('group33_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_1')
        self.a.setpassGroup(e, '!04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!04cmES7HM6wtg'])
        self.a.unlockGroup(e, True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])

    def testGroupUnlockNonempty2(self):
        e = self.a.initGroup('group33_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_2')
        self.a.setpassGroup(e, '04cmES7HM6wtg', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])
        self.a.unlockGroup(e, True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}04cmES7HM6wtg'])

    def testGroupUnlockNonempty3(self):
        e = self.a.initGroup('group33_3')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_3')
        self.a.setpassGroup(e, '!', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!'])
        self.assertRaises(RuntimeError, self.a.unlockGroup, e, True)
        del e
        e = self.a.lookupGroupByName('group33_3')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!'])

    def testGroupUnlockNonempty4(self):
        e = self.a.initGroup('group33_4')
        e[libuser.USERPASSWORD] = '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group33_4')
        self.assertEqual(e[libuser.GROUPPASSWORD],
                         ['{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='])
        self.assertRaises(RuntimeError, self.a.unlockGroup, e, True)

    def testGroupIsLocked1(self):
        e = self.a.initGroup('group26_1')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group26_1')
        self.a.setpassGroup(e, '!05/lfLEyErrp2', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}!05/lfLEyErrp2'])
        self.assertEqual(self.a.groupIsLocked(e), 1)
        
    def testGroupIsLocked2(self):
        e = self.a.initGroup('group26_2')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group26_2')
        self.a.setpassGroup(e, '05/lfLEyErrp2', True)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}05/lfLEyErrp2'])
        self.assertEqual(self.a.groupIsLocked(e), 0)
        
    def testGroupSetpass1(self):
        e = self.a.initGroup('group27_1')
        e[libuser.GROUPPASSWORD] = '{CRYPT}06aZrb3pzuu/6'
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group27_1')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}06aZrb3pzuu/6'])
        self.a.setpassGroup(e, 'password', False)
        crypted = crypt.crypt('password', e[libuser.GROUPPASSWORD][0][7:])
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}' + crypted])

    def testGroupSetpass2(self):
        e = self.a.initGroup('group27_2')
        e[libuser.GROUPPASSWORD] = ['unknown', '{CRYPT}06aZrb3pzuu/6']
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group27_2')
        v = e[libuser.GROUPPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown', '{CRYPT}06aZrb3pzuu/6'])
        self.a.setpassGroup(e, 'password', False)
        v = e[libuser.GROUPPASSWORD]
        v.sort()
        crypted = crypt.crypt('password', v[1][7:])
        self.assertEqual(v, ['unknown', '{CRYPT}' + crypted])

    def testGroupSetpass3(self):
        e = self.a.initGroup('group27_3')
        e[libuser.GROUPPASSWORD] = ['unknown1', 'unknown2']
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group27_3')
        v = e[libuser.GROUPPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown1', 'unknown2'])
        self.a.setpassGroup(e, 'password', False)
        crypted = crypt.crypt('password', e[libuser.GROUPPASSWORD][0][7:])
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}' + crypted])

    def testGroupRemovepass1(self):
        e = self.a.initGroup('group28_1')
        e[libuser.GROUPPASSWORD] = '{CRYPT}07Js7N.eEhbgs'
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group28_1')
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}07Js7N.eEhbgs'])
        self.a.removepassGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}'])

    def testGroupRemovepass2(self):
        e = self.a.initGroup('group28_2')
        e[libuser.GROUPPASSWORD] = ['unknown', '{CRYPT}07Js7N.eEhbgs']
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group28_2')
        v = e[libuser.GROUPPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown', '{CRYPT}07Js7N.eEhbgs'])
        self.a.removepassGroup(e)
        v = e[libuser.GROUPPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown', '{CRYPT}'])

    def testGroupRemovepass3(self):
        e = self.a.initGroup('group28_3')
        e[libuser.GROUPPASSWORD] = ['unknown1', 'unknown2']
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group28_3')
        v = e[libuser.GROUPPASSWORD]
        v.sort()
        self.assertEqual(v, ['unknown1', 'unknown2'])
        self.a.removepassGroup(e)
        self.assertEqual(e[libuser.GROUPPASSWORD], ['{CRYPT}'])

    def testGroupsEnumerate(self):
        e = self.a.initGroup('group29_1')
        self.a.addGroup(e)
        e = self.a.initGroup('group29_2')
        self.a.addGroup(e)
        v = self.a.enumerateGroups('group29*')
        v.sort()
        self.assertEqual(v, ['group29_1', 'group29_2'])

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

    def testGroupsEnumerateFull(self):
        e = self.a.initGroup('group31_1')
        self.a.addGroup(e)
        e = self.a.initGroup('group31_2')
        self.a.addGroup(e)
        v = map(lambda x: x[libuser.GROUPNAME],
                self.a.enumerateGroupsFull('group31*'))
        v.sort()
        self.assertEqual(v, [['group31_1'], ['group31_2']])

    def tearDown(self):
        del self.a


if __name__ == '__main__':
    unittest.main()
