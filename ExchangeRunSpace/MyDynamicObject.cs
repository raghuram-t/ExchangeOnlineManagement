using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExchangeRunSpace
{
    public class MyDynamicObject
    {
        public static void AddProperty(ExpandoObject Expando, string PropertyName, object PropertyValue)
        {

            IDictionary<string, object> currentExpando = (IDictionary<string, object>)Expando;

            if (currentExpando.ContainsKey(PropertyName))
            {
                currentExpando[PropertyName] = PropertyValue;
            }
            else
            {
                currentExpando.Add(PropertyName, PropertyValue);
            }
        }

    }
}
