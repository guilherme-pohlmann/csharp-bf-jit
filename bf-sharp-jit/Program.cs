using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

MemoryStream m;

m.TryGetBuffer(out var seg);
new ReadOnlySpan<byte>(seg.Array, seg.Offset, seg.Count)
var code =  "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.";
//var ops = Parser.Parse(code).ToList();

new JitCompiler().foo();

public class JitCompiler
{
    [DllImport("libc.so.6", SetLastError = true)]
    private static extern IntPtr mmap(IntPtr addr, UIntPtr length, MmapProt prot, MmapFlags flags, int fd, IntPtr offset);

    [Flags]
    public enum MmapProt : int
    {
        PROT_NONE = 0,
        PROT_READ = 1,
        PROT_WRITE = 2,
        PROT_EXEC = 4
    }

    [Flags]
    public enum MmapFlags : int
    {
        MAP_SHARED = 1,
        MAP_PRIVATE = 2,
        MAP_ANONYMOUS = 32
    }
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

    [Flags]
    public enum AllocationType : uint
    {
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        RESET = 0x80000,
        LARGE_PAGES = 0x20000000,
        PHYSICAL = 0x400000,
        TOP_DOWN = 0x100000,
        WRITE_WATCH = 0x200000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        GUARD_Modifierflag = 0x100,
        NOCACHE_Modifierflag = 0x200,
        WRITECOMBINE_Modifierflag = 0x400
    }
    
    unsafe public void foo()
    {
        var ptr = VirtualAlloc(IntPtr.Zero, new UIntPtr(4096), AllocationType.COMMIT | AllocationType.RESERVE, MemoryProtection.EXECUTE_READWRITE);

        ref byte b = ref Unsafe.As<IntPtr, byte>(ref ptr);
        var x = new Span<byte>(ptr.ToPointer(), 4096);
        
        
        Console.WriteLine();
    }
}

public enum OpKind {
    Inc,
    Dec,
    Left,
    Right,
    Input,
    Output,
    EndLoop,
    BeginLoop,
    Nop
}

public static class OpKindExtensions
{
    public static OpKind AsOpKind(this char c)
    {
        return c switch
        {
            '+' => OpKind.Inc,
            '-' => OpKind.Dec,
            '<' => OpKind.Left,
            '>' => OpKind.Right,
            '.' => OpKind.Output,
            ',' => OpKind.Input,
            '[' => OpKind.BeginLoop,
            ']' => OpKind.EndLoop,
            _ => OpKind.Nop
        };
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct Operation(OpKind kind, int operand)
{
    public OpKind Kind = kind;
    public int Operand = operand;
}


[StructLayout(LayoutKind.Sequential)]
public ref struct Lexer
{
    private readonly ReadOnlySpan<char> Code;
    private int pos;
    
    public Lexer(ReadOnlySpan<char> code)
    {
        Code = code;
    }

    public char Next()
    {
        while (HasNext() && !IsValidBf(Code[pos]))
            pos++;
        
        if (!HasNext())
            return '0';

        char c = Code[pos];
        pos++;

        return c;
    }

    public int Pos => pos;
    
    private bool HasNext() => pos < Code.Length;
    
    private static bool IsValidBf(char c)
    {
        const string validChars = "+-.,[]><";
        return validChars.Contains(c);
    }
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Parser
{
    public static IEnumerable<Operation> Parse(ReadOnlySpan<char> code)
    {
        var lexer = new Lexer(code);
        var ops = new List<Operation>();
        var addrs = new Stack<int>();

        var current = lexer.Next();
        
        while (current != '0')
        {
            switch (current.AsOpKind())
            {
                case OpKind.Inc:
                case OpKind.Dec:
                case OpKind.Left:
                case OpKind.Right:
                case OpKind.Input:
                case OpKind.Output:

                    var operand = 1;
                    var next = lexer.Next();
                    
                    while (current == next)
                    {
                        operand++;
                        next = lexer.Next();
                    }
                    
                    ops.Add(new Operation(current.AsOpKind(), operand));
                    current = next;
                    break;
            
                case OpKind.BeginLoop:

                    addrs.Push(ops.Count);
                    ops.Add(new Operation(OpKind.BeginLoop, 0));

                    current = lexer.Next();
                    break;
                
                case OpKind.EndLoop:
                    if (addrs.Count == 0)
                    {
                        Console.WriteLine($"ERROR: Missing matching closing loop ] at pos: {lexer.Pos}");
                        Environment.Exit(1);
                    }

                    var addr = addrs.Pop();
                    ops.Add(new Operation(OpKind.EndLoop, addr + 1));

                    CollectionsMarshal.AsSpan(ops)[addr].Operand = ops.Count;
                    current = lexer.Next();
                break;
                    
                default:
                    ops.Add(new Operation(OpKind.Nop, 0));
                    current = lexer.Next();
                    break;
            }
        }

        return ops;
    }
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Interpreter
{
    public static void Interpret(IReadOnlyList<Operation> operations)
    {
        var memory = new byte[32];
        var cell = 0;
        var ip = 0;

        while (ip < operations.Count)
        {
            var op = operations[ip];
    
            switch (op.Kind)
            {
                case OpKind.Inc:
                    memory[cell] += (byte)op.Operand;
                    ip++;
                    break;
        
                case OpKind.Dec:
                    memory[cell] -= (byte)op.Operand;
                    ip++;
                    break;
        
                case OpKind.Left:
                    cell -= op.Operand;
                    ip++;
                    break;
        
                case OpKind.Right:
                    cell += op.Operand;
                    ip++;
                    break;
        
                case OpKind.Output:
                    Console.Write((char)memory[cell]);
                    ip++;
                    break;
        
                case OpKind.Input:
                    memory[cell] = (byte)Console.Read();
                    ip++;
                    break;
        
                case OpKind.BeginLoop:
                    if (memory[cell] == 0)
                        ip = op.Operand;
                    else
                        ip++;

                    break;
        
                case OpKind.EndLoop:
                    if (memory[cell] != 0)
                        ip = op.Operand;
                    else
                        ip++;
                    break;
                
                case OpKind.Nop:
                    ip++;
                    break;
            }
        }
    }
}