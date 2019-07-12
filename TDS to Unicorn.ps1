function New-SitecoreItem{
    param
    (
        [Parameter( Position=0 )]
        [System.Xml.XmlElement] $elem,
        [string] $database
    )

    $sitecoreItem = new-object PSObject
    $sitecoreItem | Add-Member -MemberType NoteProperty -Name Database -Value $database
    $sitecoreItem | Add-Member -MemberType NoteProperty -Name Itempath -Value $elem.Attributes["Include"].Value.Replace(".item","")
    $sitecoreItem | Add-Member -MemberType NoteProperty -Name Child -Value $elem.ChildItemSynchronization
    $sitecoreItem | Add-Member -MemberType NoteProperty -Name AlwaysInclude -Value $elem.ItemDeployment

    return $sitecoreItem
}

function Get-PredicateName{
    #[CmdletBinding()]
    param(
        [ref]$nameIndex,
        $layer,
        $filename,
        $type,
        $database
        )
        $value = "$layer.$filename.$type.$database"

        $sufix = ""
        $count = -1
        do
        {
            $count++
            if($count -ne 0)
            {
                $tempFileName = "$fileName$count"
                $value = "$layer.$tempFileName.$type.$database"
            }
            
            if(($nameIndex.Value).Contains($value))
            {
                continue
            }

            if(!($nameIndex.Value).Contains($value))
            {
                ($nameIndex.Value).Add($value)
                break
            }

            
    
        }while(($nameIndex.Value).Contains($value) -eq $true)
        
        return $value
}

function GenerateModuleConfig{
    [CmdletBinding()]
    param (
        $namespace,
        $nodes,
        $layer
    )
    
    $resetPrev = "This is a random text"
    $preItem = $resetPrev
    $nameIndex = New-Object System.Collections.Generic.List[System.Object]

    foreach($node in $nodes)
    {
        $scpath = $node.Itempath.replace('.item','')
        $child = $node.Child
        $always = $node.AlwaysInclude
        $database = $node.Database
        
        $path = $scpath.Replace("\","/")
            $filename = $path.Substring($path.LastIndexOf("/") + 1).Replace(" ","").Replace("_","")
            $type = GetSectionName $path

        $nameValue = Get-PredicateName ([ref]$nameIndex) $layer $filename $type $database
        #$baseItemList = $baseItemList | Sort
        if( $baseItemList -inotcontains $scpath)
        {
           # Write-Host $scpath $child $always
            
            $curItem = $scpath

            
            if($child -eq "KeepAllChildrenSynchronized")
            {
                
                if($scpath.StartsWith($preItem) -ne "True")
                {
                    $preItem = $curItem
                    Write-Host "     <include name=""$nameValue"" database=""$database"" path=""/$path"" />"
                }
                elseif($child -eq "NoChildSynchronization")
                {
                    #$preItem = $resetPrev
                    Write-Host $scpath $child $always
                    Write-Host "     <include name=""$nameValue"" database=""$database"" path=""/$path"" ><exclude children=""true"" /></include>"
                
                }
            }
            
            elseif($child -eq "NoChildSynchronization")
            {
                $preItem = $resetPrev
                #Write-Host $scpath $child $always
                Write-Host "     <include name=""$nameValue"" database=""$database"" path=""/$path"" ><exclude children=""true"" /></include>"
                
            }
            else
            {
                Write-Host $scpath $child $always -ForegroundColor Red -BackgroundColor White
            }
        }
        elseif( ($baseItemList.Contains($scpath) -eq $true)  -and ($layer -like "*Foundation.Serialization*"))
        {

            if($child -eq "KeepAllChildrenSynchronized")
            {
                Write-Host "     <include name=""$nameValue"" database=""$database"" path=""/$path"" />"
            }
            elseif($child -eq "NoChildSynchronization")
            {
                $preItem = $resetPrev
                #Write-Host $scpath $child $always
                Write-Host "     <include name=""$nameValue"" database=""$database"" path=""/$path"" ><exclude children=""true"" /></include>"
            }
            else
            {
                Write-Host $scpath $child $always -ForegroundColor Red -BackgroundColor White
            }
        }
    }
}

function GetSectionName{
[CmdletBinding()]
param ($path)

    $contentType = "Content"
    #Write-Host $path path

    if($path.StartsWith("sitecore/content","CurrentCultureIgnoreCase") -eq "True")
    {
        $contentType = "Content"
    }
    elseif($path.StartsWith("sitecore/media library","CurrentCultureIgnoreCase") -eq "True")
    {
        $contentType = "Media"
    }
    elseif($path.StartsWith("sitecore/templates/Branch","CurrentCultureIgnoreCase") -eq "True")
    {
        $contentType = "Branch"
    }
    elseif($path.StartsWith("sitecore/templates","CurrentCultureIgnoreCase") -eq "True")
    {
        $contentType = "Template"
    }
    elseif($path.StartsWith("sitecore/layout","CurrentCultureIgnoreCase") -eq "True")
    {
        $contentType = "Layout"
    }
    elseif($path.StartsWith("sitecore/system","CurrentCultureIgnoreCase") -eq "True")
    {
        $contentType = "System"
    }
    
    return $contentType    
   
}

function GetDependency{
[CmdletBinding()]
param ($layer)
    $dependency = "SOMETHINGWRONGHERE"

    if($layer -eq "Feature")
    {
        $dependency = "Foundation.*"
    }
    elseif($layer -eq "Project")
    {
        $dependency = "Foundation.*,Feature.*,Project.Common"
    }
    elseif($layer -eq "Foundation")
    {
        $dependency = "Foundation.Serialization"
    }

    return $dependency
}

function PrepareBaseItemlist
{
    [CmdletBinding()]
    param ($groupProject)
    $key = $groupProject | ? { $_ -Like "*$SerializeFoundationPrj*"}

    $projName = $key.Replace($key.Substring($key.IndexOf(".")),"")
    $configName = $key.Replace("$projName.","")
    $desc = $key.replace("."," " )
    $layer = $configName.Replace($configName.Substring($configName.LastIndexOf(".")),"")
    $moduleName = $configName.replace("$layer.","")
    $dependency = GetDependency $layer

    if($dependency -eq $configName)
    {
        $dependency = ""
    }
    $baseItemList = @()
    foreach($file in $grpscProject.$key)
        {
           # Write-Host $prg

            $xml = [xml](Get-Content $file)
            $ns = new-object Xml.XmlNamespaceManager $xml.NameTable
            $ns.AddNamespace("msb", "http://schemas.microsoft.com/developer/msbuild/2003")
            $database = $xml.Project.PropertyGroup[0].SitecoreDatabase
            $namespace = $xml.Project.PropertyGroup[0].Name
    
            $sitecoreNodes = $xml.selectnodes("//msb:SitecoreItem",$ns)
            $count = $sitecoreNodes | measure
            
            $baseItemList += $sitecoreNodes | % { return New-SitecoreItem $_ -Database $database } | 
                                select -ExpandProperty  ItemPath -Unique 

            $baseItemList = $baseItemList | Get-Unique | Sort 
        }
        return $baseItemList
}

function ProcessGroup{

[CmdletBinding()]
param ($groupProject)
    

    $baseItemList = PrepareBaseItemlist $groupProject.Keys
    foreach($key in  $groupProject.Keys)
    {
        
        #$configName = $key.Replace("$projectName.","")
        $projName = $key.Replace($key.Substring($key.IndexOf(".")),"")
        #Write-Host "Project Name $projName"
        $configName = $key.Replace("$projName.","")
        $desc = $key.replace("."," " )
        $layer = $configName.Replace($configName.Substring($configName.LastIndexOf(".")),"")
        #Write-Host "Layer $layer"
        $moduleName = $configName.replace("$layer.","")
        $dependency = GetDependency $layer

        if($dependency -eq $configName)
        {
            $dependency = ""
        }

        Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
       
        Write-Host "   <configuration name=""$configName"" description=""$desc"" dependencies=""$dependency"" extends="""">" #$projectName.$layer
        Write-Host "    <predicate>"
        
        $sitecoreItems = @()
        #

        foreach($file in $grpscProject.$key)
        {
           # Write-Host $prg

            $xml = [xml](Get-Content $file)
            $ns = new-object Xml.XmlNamespaceManager $xml.NameTable
            $ns.AddNamespace("msb", "http://schemas.microsoft.com/developer/msbuild/2003")
            $database = $xml.Project.PropertyGroup[0].SitecoreDatabase
            $namespace = $xml.Project.PropertyGroup[0].Name
    
            $sitecoreNodes = $xml.selectnodes("//msb:SitecoreItem",$ns)
            $count = $sitecoreNodes | measure
            
            $sitecoreItems += $sitecoreNodes | % { return New-SitecoreItem $_ -Database $database } | 
                                select -Property Database, ItemPath, Child, AlwaysInclude -Unique 

            $sitecoreItems = $sitecoreItems | select -Property Database, ItemPath, Child, AlwaysInclude -Unique | Sort -Property Database,ItemPath
        }
        GenerateModuleConfig $namespace $sitecoreItems $layer


Write-Host @"
    </predicate>
    <rolePredicate>
        <include domain="modules" pattern="^Feature $moduleName .*$" />
    </rolePredicate>
    </configuration>
"@
       
    }
}

clear
$nameIndex =@()
$baseItemList = @()
$projectName = "ProjectName"
$FolderPath = "C:\ProjectName\src\"
$SerializeFoundationPrj = "Foundation.Serialization"

Set-Location -Path $FolderPath
$scproj = Get-ChildItem -Path .\ -Filter *Foundation.*.scproj -Recurse -File -Name | ForEach-Object {$FolderPath + $_} | Sort #| % { Write-Host $_}


$uniquescproject = $scproj | 
                        % {[io.path]::GetFileNameWithoutExtension($_).replace([io.path]::GetFileNameWithoutExtension($_).Substring([io.path]::GetFileNameWithoutExtension($_).LastIndexOf(".")),"")} |
                        Sort | 
                        Get-Unique


$grpscProject = @{}
foreach($u in  $uniquescproject)
{
    #Write-Host $u
    $grpscProject[$u] = @()
    foreach($p in $scproj)
    {
        #Write-Host $p - $u

        if($p -like "*$u*")
        {
           # Write-Host "maching $p"
            $grpscProject[$u] += $p
        }
    }

    #foreach($m in $grpscProject[$u])
    #{
    #    Write-Host $m
    #}
}

Write-Host '<configuration xmlns:patch="http://www.sitecore.net/xmlconfig/" xmlns:role="http://www.sitecore.net/xmlconfig/role/">'
Write-Host ' <sitecore role:require="Standalone or ContentManagement">'
Write-Host '  <unicorn>'
ProcessGroup $grpscProject
Write-Host '  </unicorn>'
Write-Host ' </sitecore>'
Write-Host '</configuration>'
