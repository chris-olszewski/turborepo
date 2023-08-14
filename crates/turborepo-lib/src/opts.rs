use anyhow::{anyhow, Result};
use turbopath::AnchoredSystemPathBuf;
use turborepo_cache::CacheOpts;

use crate::{
    cli::{Command, DryRunMode, EnvMode, LogPrefix, RunArgs},
    daemon::{DaemonClient, DaemonConnector},
    Args,
};

#[derive(Debug)]
pub struct Opts<'a> {
    pub cache_opts: CacheOpts<'a>,
    pub run_opts: RunOpts<'a>,
    pub runcache_opts: RunCacheOpts,
    pub scope_opts: ScopeOpts,
}

impl<'a> TryFrom<&'a Args> for Opts<'a> {
    type Error = anyhow::Error;

    fn try_from(args: &'a Args) -> std::result::Result<Self, Self::Error> {
        let Some(Command::Run(run_args)) = &args.command else {
            return Err(anyhow!("Expected run command"));
        };
        let run_opts = RunOpts::try_from(run_args.as_ref())?;
        let cache_opts = CacheOpts::from(run_args.as_ref());
        let scope_opts = ScopeOpts::try_from(run_args.as_ref())?;

        Ok(Self {
            run_opts,
            cache_opts,
            scope_opts,
            runcache_opts: RunCacheOpts::default(),
        })
    }
}

#[derive(Debug, Default)]
pub struct RunCacheOpts {
    pub(crate) output_watcher: Option<DaemonClient<DaemonConnector>>,
}

#[derive(Debug)]
pub struct RunOpts<'a> {
    pub(crate) tasks: &'a [String],
    concurrency: u32,
    parallel: bool,
    pub(crate) env_mode: EnvMode,
    // Whether or not to infer the framework for each workspace.
    pub(crate) framework_inference: bool,
    profile: Option<&'a str>,
    continue_on_error: bool,
    passthrough_args: &'a [String],
    pub(crate) only: bool,
    dry_run: bool,
    pub(crate) dry_run_json: bool,
    pub graph_dot: bool,
    pub graph_file: Option<&'a str>,
    pub(crate) no_daemon: bool,
    pub(crate) single_package: bool,
    log_prefix: LogPrefix,
    summarize: Option<Option<bool>>,
    pub(crate) experimental_space_id: Option<String>,
}

const DEFAULT_CONCURRENCY: u32 = 10;

impl<'a> TryFrom<&'a RunArgs> for RunOpts<'a> {
    type Error = anyhow::Error;

    fn try_from(args: &'a RunArgs) -> Result<Self> {
        let concurrency = args
            .concurrency
            .as_deref()
            .map(parse_concurrency)
            .transpose()?
            .unwrap_or(DEFAULT_CONCURRENCY);

        let (graph_dot, graph_file) = match &args.graph {
            Some(file) if file.is_empty() => (true, None),
            Some(file) => (false, Some(file.as_str())),
            None => (false, None),
        };

        Ok(Self {
            tasks: args.tasks.as_slice(),
            log_prefix: args.log_prefix,
            summarize: args.summarize,
            experimental_space_id: args.experimental_space_id.clone(),
            framework_inference: args.framework_inference,
            env_mode: args.env_mode,
            concurrency,
            parallel: args.parallel,
            profile: args.profile.as_deref(),
            continue_on_error: args.continue_execution,
            passthrough_args: args.pass_through_args.as_ref(),
            only: args.only,
            no_daemon: args.no_daemon,
            single_package: args.single_package,
            graph_dot,
            graph_file,
            dry_run_json: matches!(args.dry_run, Some(DryRunMode::Json)),
            dry_run: args.dry_run.is_some(),
        })
    }
}

fn parse_concurrency(concurrency_raw: &str) -> Result<u32> {
    if let Some(percent) = concurrency_raw.strip_suffix('%') {
        let percent = percent.parse::<f64>()?;
        return if percent > 0.0 && percent.is_finite() {
            Ok((num_cpus::get() as f64 * percent / 100.0).max(1.0) as u32)
        } else {
            Err(anyhow!(
                "invalid percentage value for --concurrency CLI flag. This should be a percentage \
                 of CPU cores, between 1% and 100% : {}",
                percent
            ))
        };
    }
    match concurrency_raw.parse::<u32>() {
        Ok(concurrency) if concurrency > 1 => Ok(concurrency),
        Ok(_) | Err(_) => Err(anyhow!(
            "invalid value for --concurrency CLI flag. This should be a positive integer greater \
             than or equal to 1: {}",
            concurrency_raw
        )),
    }
}

#[derive(Debug)]
pub struct ScopeOpts {
    pub pkg_inference_root: Option<AnchoredSystemPathBuf>,
}

impl<'a> TryFrom<&'a RunArgs> for ScopeOpts {
    type Error = anyhow::Error;

    fn try_from(args: &'a RunArgs) -> std::result::Result<Self, Self::Error> {
        let pkg_inference_root = args
            .pkg_inference_root
            .as_ref()
            .map(AnchoredSystemPathBuf::from_raw)
            .transpose()?;
        Ok(Self { pkg_inference_root })
    }
}

impl<'a> From<&'a RunArgs> for CacheOpts<'a> {
    fn from(run_args: &'a RunArgs) -> Self {
        CacheOpts {
            override_dir: run_args.cache_dir.as_deref(),
            skip_filesystem: run_args.remote_only,
            workers: run_args.cache_workers,
            ..CacheOpts::default()
        }
    }
}
