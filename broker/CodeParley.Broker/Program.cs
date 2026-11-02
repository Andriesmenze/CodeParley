using CodeParley.Broker;
using CodeParley.Broker.Cli;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Administrative / credential-bearing verbs run as a console command and exit. With no verb (how the
// SCM starts us), we host the Windows service.
string verb = args.Length > 0 ? args[0].ToLowerInvariant() : "run";
switch (verb)
{
    case "install":           return BrokerCli.Install(args);
    case "uninstall":         return BrokerCli.Uninstall(args);
    case "provision":         return BrokerCli.Provision(args);
    case "deprovision":       return BrokerCli.Deprovision(args);
    case "capabilities":      return BrokerCli.Capabilities(args);
    case "self-test":         return BrokerCli.SelfTest(args);
    case "self-test-classify":return BrokerCli.SelfTestClassify(args);
    case "run":               break;
    default:
        Console.Error.WriteLine($"unknown verb '{verb}' (expected: run|install|uninstall|provision|deprovision|capabilities|self-test|self-test-classify)");
        return 2;
}

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = BrokerConstants.ServiceName);
builder.Services.AddHostedService<BrokerService>();
builder.Build().Run();
return 0;
