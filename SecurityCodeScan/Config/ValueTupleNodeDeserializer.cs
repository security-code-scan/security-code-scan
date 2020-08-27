#nullable disable
using System;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace SecurityCodeScan.Config
{
    internal class ValueTupleNodeDeserializer : INodeDeserializer
    {
        public bool Deserialize(IParser parser, Type expectedType, Func<IParser, Type, object> nestedObjectDeserializer, out object value)
        {
            if (expectedType.IsGenericType && expectedType.GetGenericTypeDefinition() == typeof(ValueTuple<,>))
            {
                var pairArgs = expectedType.GetGenericArguments();
                var args = new object[pairArgs.Length];

                parser.Consume<MappingStart>();

                for (int i = 0; i < pairArgs.Length; ++i)
                {
                    var scalar = parser.Consume<Scalar>();
                    var stringValue = scalar.Value;

                    if (pairArgs[i] == typeof(int))
                        args[i] = int.Parse(stringValue);
                    else if (stringValue == "True")
                        args[i] = true;
                    else if (stringValue == "False")
                        args[i] = false;
                    else if (pairArgs[i] == typeof(object) && scalar.Style == ScalarStyle.Plain)
                        args[i] = int.Parse(stringValue);
                    else
                        args[i] = stringValue;
                }

                parser.Consume<MappingEnd>();

                value = Activator.CreateInstance(expectedType, args);
                return true;
            }

            value = null;
            return false;
        }
    }
}
