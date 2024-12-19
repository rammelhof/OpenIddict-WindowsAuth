using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Runtime.Versioning;

namespace IdentityServer.ActiveDirectory
{
    /// <summary>
    /// Represents a user represented by a logon account name
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class User : ADObject
    {
        public User() { }

        /// <summary>
        /// Class constructor. Accepts a user's logon name or distinguished name and gets the associated user account in active directory.
        /// </summary>
        /// <param name="userName"></param>
        public User(String userName)
        {
            if (userName == null || userName == "")
                throw new ArgumentNullException();

            if (userName.Contains("LDAP://"))
            {
                base.adobject = new DirectoryEntry(userName);
            }
            else
            {
                if (userName.Contains("\\"))
                {
                    userName = userName.Split('\\')[1];
                }

                using (DirectorySearcher search = new DirectorySearcher())
                {
                    // no local cache
                    search.CacheResults = false;

                    search.Filter = "(&(objectClass=user)(sAMAccountName=" + CleanLDAPString(userName) + "))";
                    search.PropertiesToLoad.Add("cn");
                    search.PropertiesToLoad.Add("memberOf");
                    search.PropertiesToLoad.Add("title");
                    search.PropertiesToLoad.Add("telephoneNumber");
                    search.PropertiesToLoad.Add("mobile");
                    search.PropertiesToLoad.Add("mail");
                    search.PropertiesToLoad.Add("sAMAccountName");
                    search.PropertiesToLoad.Add("displayName");
                    search.PropertiesToLoad.Add("givenName");
                    search.PropertiesToLoad.Add("userAccountControl");
                    search.PropertiesToLoad.Add("sn");
                    SearchResult result = search.FindOne();
                    base.adobject = result.GetDirectoryEntry();
                }
            }
        }

        public User(ADGuid guid) : base(guid) { }
        public User(DirectoryEntry entry) : base(entry) { }

        /// <summary>
        /// Gets true or false depending if the given flag is set or not.
        /// </summary>
        /// <param name="userDn"></param>
        /// <param name="uacflag"></param>
        /// <returns></returns>
        public bool UACValue(UACFlags uacflag)
        {
            if (((int)(base.adobject.Properties["userAccountControl"].Value) & (int)uacflag) != 0)
            {
                return true;
            }
            return false;
        }

        #region General Tab
        /// <summary>
        /// Gets or sets the user's given name
        /// </summary>
        public String FirstName
        {
            get { return (String)base.adobject.Properties["givenName"].Value; }
            set { base.adobject.Properties["givenName"].Value = value.Length > 0 ? value : null; }
        }

        /// <summary>
        /// Gets or sets the user's last name
        /// </summary>
        public String LastName
        {
            get { return (String)base.adobject.Properties["sn"].Value; }
            set { base.adobject.Properties["sn"].Value = value.Length > 0 ? value : null; }
        }

        /// <summary>
        /// Gets or sets the user's display name
        /// </summary>
        public string DisplayName
        {
            get { return (String)base.adobject.Properties["displayName"].Value; }
            set { base.adobject.Properties["displayName"].Value = value.Length > 0 ? value : null; }
        }

        /// <summary>
        /// Gets or sets the user's email address
        /// </summary>
        public String Email
        {
            get { return (String)base.adobject.Properties["mail"].Value; }
            set { base.adobject.Properties["mail"].Value = value.Length > 0 ? value : null; }
        }

        #endregion

        #region Telephone Tab
        
        /// <summary>
        /// Gets or sets the user's mobile phone number
        /// </summary>
        public String MobilePhone
        {
            get { return (String)base.adobject.Properties["mobile"].Value; }
            set { base.adobject.Properties["mobile"].Value = value.Length > 0 ? value : null; }
        }

        /// <summary>
        /// Gets or sets the user's telephone number
        /// </summary>
        public String TelephoneNumber
        {
            get { return (String)base.adobject.Properties["telephoneNumber"].Value; }
            set { base.adobject.Properties["telephoneNumber"].Value = value.Length > 0 ? value : null; }
        }

        #endregion

        #region Organization Tab
        /// <summary>
        /// Gets or sets the user's title
        /// </summary>
        public String Title
        {
            get { return (String)base.adobject.Properties["title"].Value; }
            set { base.adobject.Properties["title"].Value = value.Length > 0 ? value : null; }
        }
        #endregion

        #region Active Directory Settings
        public String Username
        {
            get { return (String)base.adobject.Properties["sAMAccountName"].Value; }
        }
        #endregion

        /// <summary>
        /// Gets a List String containing the LDAP Group names this user is a member of
        /// </summary>
        public List<String> Groups
        {
            get
            {
                List<String> result = new List<String>();
                PropertyValueCollection values = base.adobject.Properties["memberOf"];
                IEnumerator en = values.GetEnumerator();

                while (en.MoveNext())
                {
                    if (en.Current != null)
                    {
                        result.Add(en.Current.ToString());
                    }
                }

                return result;
            }
        }

        /// <summary>
        /// Same as Groups, but only returns the common name rather than the whole LDAP string
        /// </summary>
        public List<String> GroupsCommonName
        {
            get
            {
                List<String> result = new List<String>();

                foreach (String group in Groups)
                {
                    foreach (String el in group.Split(new char[] { ',' }))
                    {
                        if (el.StartsWith("CN="))
                        {
                            result.Add(el.Substring(3));
                        }
                    }
                }

                return result;
            }
        }

        /// <summary>
        /// Enumation of user account flags
        /// </summary>
        public enum UACFlags
        {
            SCRIPT = 0x0001,
            ACCOUNTDISABLE = 0x0002,
            HOMEDIR_REQUIRED = 0x0008,
            LOCKOUT = 0x0010,
            PASSWD_NOTREQD = 0x0020,
            PASSWD_CANT_CHANGE = 0x0040,
            ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080,
            TEMP_DUPLICATE_ACCOUNT = 0x0100,
            NORMAL_ACCOUNT = 0x0200,
            INTERDOMAIN_TRUST_ACCOUNT = 0x0800,
            WORKSTATION_TRUST_ACCOUNT = 0x1000,
            SERVER_TRUST_ACCOUNT = 0x2000,
            DONT_EXPIRE_PASSWORD = 0x10000,
            MNS_LOGON_ACCOUNT = 0x20000,
            SMARTCARD_REQUIRED = 0x40000,
            TRUSTED_FOR_DELEGATION = 0x80000,
            NOT_DELEGATED = 0x100000,
            USE_DES_KEY_ONLY = 0x200000,
            DONT_REQ_PREAUTH = 0x400000,
            PASSWORD_EXPIRED = 0x800000,
            TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
        };
    }
}
