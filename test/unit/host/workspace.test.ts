import { mkdir, mkdtemp, realpath, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resolveNewWorkspacePath } from '../../../src/host/service/workspace.ts'

describe('workspace output authorization', () => {
  let root: string
  let workspace: string

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'dsh-univer-workspace-')))
    workspace = join(root, 'workspace')
    await mkdir(workspace)
  })

  afterEach(async () => {
    await rm(root, { recursive: true, force: true })
  })

  it('authorizes a missing output inside the workspace', async () => {
    const resolved = await resolveNewWorkspacePath(workspace, 'out/report.pdf')
    expect(resolved.path).toBe(join(workspace, 'out', 'report.pdf'))
  })

  it.each([
    ['the output itself', 'escape.pdf', 'escape.pdf'],
    ['an ancestor directory', 'escape', 'escape/report.pdf']
  ])('refuses a dangling symlink as %s', async (_label, link, output) => {
    await symlink(join(root, 'outside', 'target'), join(workspace, link))
    await expect(resolveNewWorkspacePath(workspace, output)).rejects.toMatchObject({
      code: 'INVALID_FILE_PATH'
    })
  })
})
