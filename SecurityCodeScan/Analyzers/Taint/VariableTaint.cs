using System;

namespace SecurityCodeScan.Analyzers.Taint
{
    [Flags]
    internal enum VariableTaint : ulong
    {
        /// <summary>
        /// Value is not determined
        /// </summary>
        Unset    = 0b000,
        /// <summary>
        /// Value from unknown source
        /// </summary>
        Unknown  = 0b001,
        /// <summary>
        /// Value from known insecure source
        /// </summary>
        Tainted  = 0b010,
        /// <summary>
        /// Constant hardcoded value
        /// </summary>
        Constant = 0b100,
        /// <summary>
        /// Trusted value
        /// </summary>
        Safe = UInt64.MaxValue & ~0b111ul, // set last three bits to zero, all other bits are used by sanitizers. Safe == bits of all possible sanitizers set.
    }
}
