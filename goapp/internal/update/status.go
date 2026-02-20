package update

import (
    "context"
)

type Status struct {
    RepoOK        bool
    Branch        string
    CurrentVer    string
    CurrentCommit string
    LatestVer     string
    LatestCommit  string
    BehindCount   string
    Note          string
}

func GetStatus(ctx context.Context, runner GitRunner, fetchRemote bool) Status {
    st := Status{
        RepoOK:        false,
        Branch:        "-",
        CurrentVer:    "-",
        CurrentCommit: "-",
        LatestVer:     "-",
        LatestCommit:  "-",
        BehindCount:   "-",
        Note:          "",
    }

    res := runner.Run(ctx, "rev-parse", "--is-inside-work-tree")
    if !res.OK || res.Out != "true" {
        st.Note = "当前目录不是 Git 仓库。"
        return st
    }
    st.RepoOK = true

    if b := runner.Run(ctx, "rev-parse", "--abbrev-ref", "HEAD"); b.OK && b.Out != "" {
        st.Branch = b.Out
    }
    if v := runner.Run(ctx, "describe", "--tags", "--always"); v.OK && v.Out != "" {
        st.CurrentVer = v.Out
    }
    if sha := runner.Run(ctx, "rev-parse", "HEAD"); sha.OK && sha.Out != "" {
        if len(sha.Out) >= 7 {
            st.CurrentCommit = sha.Out[:7]
        } else {
            st.CurrentCommit = sha.Out
        }
    }

    branch := st.Branch
    if !fetchRemote {
        st.Note = "未请求远端信息，点击“刷新最新版本”获取最新版本。"
        if branch != "" && branch != "-" {
            latest := runner.Run(ctx, "rev-parse", "origin/"+branch)
            if latest.OK && latest.Out != "" {
                st.LatestCommit = shortSHA(latest.Out)
                if lv := runner.Run(ctx, "describe", "--tags", "--always", latest.Out); lv.OK && lv.Out != "" {
                    st.LatestVer = lv.Out
                } else {
                    st.LatestVer = st.LatestCommit
                }
                if behind := runner.Run(ctx, "rev-list", "--count", "HEAD..origin/"+branch); behind.OK && behind.Out != "" {
                    st.BehindCount = behind.Out
                    st.Note = ""
                }
            }
        }
        return st
    }

    if fetchRemote {
        fetch := runner.Run(ctx, "fetch", "origin")
        if !fetch.OK {
            st.Note = "获取远端信息失败：" + fetch.Out
            return st
        }
    }

    if branch != "" && branch != "-" {
        latest := runner.Run(ctx, "rev-parse", "origin/"+branch)
        if latest.OK && latest.Out != "" {
            st.LatestCommit = shortSHA(latest.Out)
            if lv := runner.Run(ctx, "describe", "--tags", "--always", latest.Out); lv.OK && lv.Out != "" {
                st.LatestVer = lv.Out
            } else {
                st.LatestVer = st.LatestCommit
            }
            if behind := runner.Run(ctx, "rev-list", "--count", "HEAD..origin/"+branch); behind.OK && behind.Out != "" {
                st.BehindCount = behind.Out
            }
            return st
        }
    }

    return st
}

func shortSHA(full string) string {
    if len(full) >= 7 {
        return full[:7]
    }
    return full
}
