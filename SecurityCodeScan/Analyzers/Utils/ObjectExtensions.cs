#nullable disable
using System;

namespace SecurityCodeScan.Analyzers.Utils
{
    internal static class ObjectExtensions
    {
        public static TResult TypeSwitch<TBaseType, TDerivedType1, TDerivedType2, TResult>(this TBaseType obj, Func<TDerivedType1, TResult> matchFunc1, Func<TDerivedType2, TResult> matchFunc2, Func<TBaseType, TResult> defaultFunc = null)
            where TDerivedType1 : TBaseType
            where TDerivedType2 : TBaseType
        {
            switch (obj)
            {
                case TDerivedType1 type1:
                    return matchFunc1(type1);
                case TDerivedType2 type2:
                    return matchFunc2(type2);
            }

            if (defaultFunc != null)
            {
                return defaultFunc(obj);
            }

            return default(TResult);
        }
    }
}
