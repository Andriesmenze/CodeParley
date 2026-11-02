using CodeParley.Custodian;
using CodeParley.Custodian.Cli;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Phase 5 (§4.1): this is the Windows host of the portable core; its seams are set before anything else runs.
CodeParley.Custodian.Platforms.WindowsPlatform.Configure();

// Administrative verbs run as a console command and exit. With no verb (how the SCM starts us) we host
// the Windows service. The privileged verbs (install/provision) are invoked only by the operator's
// elevated install script, never by the model.
string verb = args.Length > 0 ? args[0].ToLowerInvariant() : "run";
switch (verb)
{
    case "install":            return CustodianCli.Install(args);
    case "uninstall":          return CustodianCli.Uninstall(args);
    case "provision":          return CustodianCli.Provision(args);
    case "deprovision":        return CustodianCli.Deprovision(args);
    case "capabilities":       return CustodianCli.Capabilities(args);
    case "version":            return BuildIdentity.Print("windows");
    case "self-test-sid":      return CustodianCli.SelfTestSid(args);
    case "self-test-digest":   return CustodianCli.SelfTestDigest(args);
    case "self-test-ledger":   return CustodianCli.SelfTestLedger(args);
    case "self-test-nofollow": return CustodianCli.SelfTestNoFollow(args);
    case "self-test-ipc":      return CustodianCli.SelfTestIpc(args);
    case "self-test-content-key": return CustodianCli.SelfTestContentKey(args);
    case "self-test-store-format": return CodeParley.Custodian.Cli.StoreFormatSelfTest.Run();
    case "self-test-store-upgrade": return CodeParley.Custodian.Cli.StoreUpgradeSelfTest.Run();
    case "self-test-runtime-git": return CodeParley.Custodian.Cli.RuntimeGitSelfTest.Run();
    case "store-status":       return CodeParley.Custodian.Cli.StoreUpgradeCli.Status();
    case "store-upgrade":      return CodeParley.Custodian.Cli.StoreUpgradeCli.Upgrade(args);
    case "self-test-loop-corpus": return LoopCorpusSelfTest.Run(args);
    case "self-test-run-corpus": return RunCorpusSelfTest.Run(args);
    case "self-test-config-corpus": return ConfigCorpusSelfTest.Run(args);
    case "self-test-identity": return IdentitySelfTest.Run(args);
    case "self-test-serve":    return CustodianCli.SelfTestServe(args);
    case "probe-capture":      return CustodianCli.ProbeCapture(args);
    case "measure-codex":      return CustodianCli.MeasureCodex(args);
    case "self-test-helper":   return HelperFeasibility.Run(args);
    case "helper-probe":       return HelperFeasibility.Probe(args);
    case "self-test-appcontainer": return AppContainerFeasibility.Run(args);
    case "appcontainer-sid":   return AppContainerFeasibility.PrintSid(args);
    case "self-test-helper-principal": return HelperPrincipalFeasibility.Run(args);
    case "self-test-helper-channel": return HelperChannelSelfTest.Run(args);
    case "self-test-helper-e2e": return HelperE2eSelfTest.Run(args);
    case "self-test-helper-negatives": return HelperNegativesSelfTest.Run(args);
    case "helper-service":     return HelperHost.Run(args);
    case "install-helper":     return HelperInstall.Install(args);
    case "uninstall-helper":   return HelperInstall.Uninstall(args);
    case "run":                break;
    default:
        Console.Error.WriteLine($"unknown verb '{verb}' (install|uninstall|provision|deprovision|capabilities|version|self-test-sid|self-test-digest|self-test-ledger|self-test-nofollow|self-test-ipc|self-test-content-key|self-test-store-format|self-test-store-upgrade|self-test-runtime-git|store-status|store-upgrade|self-test-loop-corpus|self-test-run-corpus|self-test-config-corpus|self-test-identity|self-test-serve|probe-capture|measure-codex|self-test-helper|helper-probe|self-test-appcontainer|appcontainer-sid|self-test-helper-principal|self-test-helper-channel|self-test-helper-e2e|self-test-helper-negatives|helper-service|install-helper|uninstall-helper|run)");
        return 2;
}

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = CustodianConstants.ServiceName);
builder.Services.AddHostedService<CustodianService>();
builder.Build().Run();
return 0;
