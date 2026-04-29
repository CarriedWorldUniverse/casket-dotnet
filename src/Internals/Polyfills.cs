// Polyfills for netstandard2.1 — required for C# 9+ features (init, records, [Experimental])

#if NETSTANDARD2_1
namespace System.Runtime.CompilerServices
{
    // Enables 'init' property accessors on netstandard2.1 when compiling with C# 10+
    internal static class IsExternalInit { }
}

namespace System.Diagnostics.CodeAnalysis
{
    [global::System.AttributeUsage(
        global::System.AttributeTargets.Assembly |
        global::System.AttributeTargets.Module |
        global::System.AttributeTargets.Class |
        global::System.AttributeTargets.Struct |
        global::System.AttributeTargets.Enum |
        global::System.AttributeTargets.Constructor |
        global::System.AttributeTargets.Method |
        global::System.AttributeTargets.Property |
        global::System.AttributeTargets.Field |
        global::System.AttributeTargets.Event |
        global::System.AttributeTargets.Interface |
        global::System.AttributeTargets.Delegate,
        Inherited = false)]
    internal sealed class ExperimentalAttribute : global::System.Attribute
    {
        public ExperimentalAttribute(string diagnosticId) { DiagnosticId = diagnosticId; }
        public string DiagnosticId { get; }
        public string? UrlFormat { get; set; }
    }
}
#endif
