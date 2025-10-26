# 🔧 GitHub Actions Wiki Sync Troubleshooting

## Common Issues and Solutions

### 1. **Wiki Repository Doesn't Exist**

**Error:** `Failed to push to wiki repository`

**Solution:**
1. Go to your GitHub repository
2. Click on **Settings** tab
3. Scroll down to **Features** section
4. Check the **Wiki** checkbox to enable it
5. Click **Save**
6. Create at least one wiki page manually (even just a test page)
7. Re-run the GitHub Actions workflow

### 2. **Permission Issues**

**Error:** `Permission denied` or `403 Forbidden`

**Solutions:**
- **Repository permissions**: Ensure the repository allows GitHub Actions
- **Wiki permissions**: Make sure the wiki is enabled and accessible
- **Branch protection**: Check if branch protection rules are blocking the workflow

### 3. **Workflow Not Triggering**

**Issue:** Workflow doesn't run when pushing to `docs/wiki/`

**Solutions:**
- Check the workflow file is in `.github/workflows/sync-wiki.yml`
- Verify the `paths` filter includes `docs/wiki/**`
- Ensure you're pushing to the `main` branch
- Check GitHub Actions is enabled for the repository

### 4. **YAML Validation Errors**

**Error:** `Invalid YAML` in documentation

**Solution:**
- Check YAML syntax in configuration examples
- Ensure proper indentation (use spaces, not tabs)
- Validate YAML blocks in markdown files

### 5. **Link Validation Failures**

**Error:** Broken links in documentation

**Solutions:**
- Check internal links point to existing wiki pages
- Verify external links are accessible
- Update link-check-config.json to ignore problematic patterns

## Manual Wiki Setup

If the automated sync continues to fail, you can set up the wiki manually:

### Step 1: Enable Wiki
1. Go to repository **Settings**
2. Enable **Wiki** feature
3. Create a test page

### Step 2: Clone Wiki Repository
```bash
git clone https://github.com/samerfarida/mcp-ssh-orchestrator.wiki.git
cd mcp-ssh-orchestrator.wiki
```

### Step 3: Copy Content
```bash
# Copy wiki content from main repository
cp -r ../mcp-ssh-orchestrator/docs/wiki/* .
```

### Step 4: Commit and Push
```bash
git add .
git commit -m "Initial wiki content"
git push origin master
```

## Workflow Debugging

### Enable Debug Logging
Add this to the workflow for more detailed output:
```yaml
- name: Debug Information
  run: |
    echo "Repository: ${{ github.repository }}"
    echo "SHA: ${{ github.sha }}"
    echo "Event: ${{ github.event_name }}"
    echo "Ref: ${{ github.ref }}"
```

### Check Workflow Status
1. Go to **Actions** tab in your repository
2. Click on the failed workflow run
3. Expand each step to see detailed logs
4. Look for error messages and stack traces

### Common Error Messages

**`git fetch origin master` fails:**
- Wiki repository doesn't exist yet
- Solution: Enable wiki and create initial page

**`git push origin master` fails:**
- Permission issues
- Solution: Check repository settings and permissions

**`rsync` fails:**
- Source directory doesn't exist
- Solution: Ensure `docs/wiki/` directory exists

**YAML validation fails:**
- Invalid YAML syntax in examples
- Solution: Fix YAML syntax in markdown files

## Testing the Workflow

### Local Testing
```bash
# Test the sync script locally
chmod +x test-sync-workflow.sh
./test-sync-workflow.sh
```

### Manual Workflow Trigger
1. Go to **Actions** tab
2. Select **Sync Wiki Documentation**
3. Click **Run workflow**
4. Select branch and click **Run workflow**

## Success Indicators

✅ **Workflow runs successfully**
✅ **Wiki content appears in GitHub wiki**
✅ **All 16 sections are accessible**
✅ **Links work correctly**
✅ **YAML examples are valid**

## Getting Help

If issues persist:
1. Check the **Actions** tab for detailed error logs
2. Verify repository settings and permissions
3. Test the workflow manually
4. Create a GitHub issue with error details

## Next Steps

Once the workflow is working:
1. **Monitor**: Check that wiki stays in sync
2. **Update**: Modify `docs/wiki/` content as needed
3. **Validate**: Ensure all links and examples work
4. **Maintain**: Keep documentation up to date
