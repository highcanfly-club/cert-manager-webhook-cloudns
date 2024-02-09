allow_k8s_contexts('kubernetes-admin@kubernetes')

_build='remote' | 'local'

if os.name == 'nt':
    datebase=str(local("powershell -command Get-Date -Format yyyy-MM-dd"))
elif os.name == 'posix':
    datebase=str(local("date -I"))

datei=str(abs(hash(datebase)))
sha1=str(abs(hash(str(local("openssl dgst -sha1 Dockerfile")))))
Namespace='kube-certmanager'
ModuleName='my_module'
ModulePath='./'+ModuleName
CacheRegistry='ttl.sh/cloudns-webhook-dev-'+datei+'-cache'
Registry='ttl.sh/cloudns-webhook-dev-dev-'+sha1
default_registry(Registry)

load('ext://helm_resource', 'helm_resource', 'helm_repo')
load('ext://namespace', 'namespace_create')
os.putenv ( 'NAMESPACE' , Namespace )
os.putenv ( 'REGISTRY_HOST' , 'ttl.sh' )
os.putenv ( 'DOCKER_REGISTRY' , Registry ) 
os.putenv ( 'DOCKER_CACHE_REGISTRY' , CacheRegistry ) 
current_path = os.getcwd()
namespace_create(Namespace)

warn ("sha1: "+sha1)
warn ("datei: "+datei)
if _build == 'local':
    custom_build(
        'cert-manager-webhook-cloudns',
        'docker build --push -t $EXPECTED_REF .',
        ['.'],
        )
else:
    if os.name == 'nt':
        # Code à exécuter si le système d'exploitation est Windows
        warn("Running on Windows")
        custom_build('cert-manager-webhook-cloudns', 'kubectl -n %NAMESPACE% delete pod/kaniko & tar -cvz --exclude "private" --exclude "helm" --exclude "deploy" --exclude ".git" --exclude ".github" --exclude-vcs --exclude ".docker" --exclude "_sensitive_datas"  ./Dockerfile ./cloudns go.mod go.sum main.go | kubectl -n %NAMESPACE% run kaniko --image=gcr.io/kaniko-project/executor:latest --stdin=true --command -- /kaniko/executor -v info --dockerfile=Dockerfile --context=tar://stdin --destination=%EXPECTED_REF% --cache=true --cache-ttl=24h --cache-repo=%DOCKER_CACHE_REGISTRY%', [
                ModuleName
            ], skips_local_docker = True)
    elif os.name == 'posix':
        # Code à exécuter si le système d'exploitation est Linux ou MacOS
        warn("Running on Posix")
        custom_build('cert-manager-webhook-cloudns', 'kubectl -n $NAMESPACE delete pod/kaniko & tar -cvz --exclude "private" --exclude "helm" --exclude "deploy" --exclude ".git" --exclude ".github" --exclude-vcs --exclude ".docker" --exclude "_sensitive_datas"  ./Dockerfile ./cloudns go.mod go.sum main.go | kubectl -n $NAMESPACE run kaniko --image=gcr.io/kaniko-project/executor:latest --stdin=true --command -- /kaniko/executor -v info --dockerfile=Dockerfile --context=tar://stdin --destination=$EXPECTED_REF --cache=true --cache-ttl=24h --cache-repo=$DOCKER_CACHE_REGISTRY',
        [],
        skips_local_docker = True )


helm_resource('cert-manager-webhook-cloudns-helm-chart',
    'deploy/cert-manager-webhook-cloudns',
    namespace = Namespace,
    flags = ['--values=./_values.yaml', '--set', 'image.registry=ttl.sh',
             '--set', 'nodeSelector."kubernetes\.io/arch"=amd64'],
    image_deps = ['cert-manager-webhook-cloudns'],
    image_keys=[('image.registry','image.repository', 'image.tag')],
)