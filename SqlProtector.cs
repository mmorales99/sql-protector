using System;
using System.Collections.Generic;

namespace SqlProtector
{
    public class SqlProtector
    {
        private SqlProtector() { }

        internal static IList<string> SqlDictionary = new List<string>() {
            "drop",
            "or",
            "and",
            "==",
            "\"\"",
            "table",
            "select",
            "order by",
            "asc",
            "desc",
            "from",
            "where"
            // may add some more
        };

        public static event SqlInjectionEventHandler SqlInjectionDetectedEvent;

        protected static bool SearchFor(string Str) {
            // add reserved word to the list
            return (bool)SqlDictionary.Contains(Str); // returns true if its found
        }

        public static bool IsSafe(string Str) {
            if (Str == null) {
                return false;
            }
            bool ret = true;
            string[] tokenlist = Str.Split(new char[] { ' ', '\n', '\0', ';' }); // split the string if it can be splited
            foreach (string token in tokenlist) { // foreach token find if its part of sql parser
                ret = !SqlProtector.SearchFor(token);
                if (ret == false) return ret;
            }
            return ret;
        }

        public static string[] GoSafe(string Str) {
            string[] ret;
            ret = Str.Split(new char[] { ' ', '\n', '\0', ';' });
            foreach (string word in ret) {
                bool safe = SqlProtector.IsSafe(word);
                if (!safe) {
                    throw new SqlInjectionDetectedException(word);
                }
            }
            return ret;
        }

        public static bool DeepinSafen(string Str) {
            bool safe = false;
            Str = Str.ToLower();
            safe = SqlProtector.IsSafe(Str);
            string aux = "";
            for (int i = 0; i < Str.Length; i++) {
                foreach (string sqlerror in SqlDictionary) {
                    char c = sqlerror[0];
                    if (Str[i] == c) {
                        for (; i < Str.Length; i++)
                        {
                            aux += Str[i];
                            if (Str[i] == ' ')
                            {
                                break;
                            }
                        }
                        if (aux == sqlerror)
                        {
                            safe = false;
                            // may delete the token??
                            SqlInjectionArgs args = new SqlInjectionArgs(aux);
                            SqlInjectionEventHandler handler = SqlProtector.SqlInjectionDetectedEvent;
                            handler(new SqlProtector(),args);
                            throw new SqlInjectionDetectedException(aux);
                        }
                    }
                }
            }
            return safe;
        }
    }

    public class SqlInjectionException : Exception {
        public SqlInjectionException() : base("Sql section found!") { }
    }
    public class SqlInjectionDetectedException : Exception {
        public SqlInjectionDetectedException(string str) : base("Found malicios code in token: " + str) { }
    }

    public class SqlInjectionArgs : EventArgs {
        public string Message { get; private set; }
        public SqlInjectionArgs(string msg) {
            Message += $"found {msg} as malicious token";
        }
    }
    public delegate void SqlInjectionEventHandler(object protector, SqlInjectionArgs args);
    public class SqlInjectionHandler{
        public static void SqlInjectionDefaulHandler(object protector, SqlInjectionArgs args){
            Console.WriteLine("SqlInjection detected! Rejecting input.");
        }
    }
}
