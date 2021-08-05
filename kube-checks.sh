#!/bin/bash

# run like
# kube-checks.sh context namespace
# kube-checks.sh awsenviroment production

IFS=$'\n'
secret_array=()

context2=$1
namespace2=$2

# check if variables are blank or filled
if [ "$context2" != "" ] ; then
    context1="--context"
fi

if [ "$namespace2" != "" ] ; then
    namespace1="-n"
fi

# get a list of all the pods
kubectl $context1 $context2 $namespace1 $namespace2 get pods | cut -d ' ' -f 1 | tail -n +2 > pod-list.txt

for pod in $(cat pod-list.txt); do 	
	echo " - Checking $pod"
	# check if kubectl is installed, if not the install it
	installed=$(kubectl $context1 $context2 $namespace1 $namespace2 exec -it $pod -- "/tmp/kubectl" | grep "no such file or directory" | wc -l | sed 's/ //g')
	if [ "$installed" == "1" ] ; then
		kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- bash -c "apt update && apt -y install curl; curl -L -o /tmp/kubectl \"https://storage.googleapis.com/kubernetes-release/release/\$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl\"; chmod +x /tmp/kubectl"
	fi

#
# TYPE: Pod misonfiguration yaml checks
	# Based on https://labs.bishopfox.com/tech-blog/bad-pods-kubernetes-pod-privilege-escalation
	# [ ]{1,} regex matches multiple spaces
	yaml=$(kubectl $context1 $context2 $namespace1 $namespace2 get pod $pod -o yaml)
	if [[ "$yaml" =~ "privileged:[ ]{1,}true" ]] ; then
		echo "!!!! $pod is set to privileged!!!!" | tee -a issues.txt
	fi
	if [[ "$yaml" =~ "hostPID:[ ]{1,}true" ]] ; then
		echo "!!!! $pod is set to hostPID!!!!" | tee -a issues.txt
	fi
	if [[ "$yaml" =~ "allowedHostPaths" ]] ; then
		echo "!!!! $pod spec contains allowedHostPaths!!!!" | tee -a issues.txt
	fi
	if [[ "$yaml" =~ "hostNetwork:[ ]{1,}true" ]] ; then
		echo "!!!! $pod is set to hostNetwork!!!!" | tee -a issues.txt
	fi
	if [[ "$yaml" =~ "hostIPC:[ ]{1,}true" ]] ; then
		echo "!!!! $pod is set to hostIPC!!!!" | tee -a issues.txt
		kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- ls /dev/shm
	fi
	if [[ "$yaml" =~ "readOnlyRootFilesystem" ]] ; then
		echo "!!!! $pod allows read access to root filesystem!!!!" | tee -a issues.txt
		kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- ls /dev/shm
	fi


	# check if pod is completed or running? if completed skip the rest
	pod_status=$(kubectl $context1 $context2 $namespace1 $namespace2 get pod $pod | tail -n +2 | sed 's/  */ /g' | cut -d ' ' -f 3)
	if [[ "$pod_status" =~ "Completed" ]] ; then
		# skip running in Completed pod
		:
	else

		# Checking for excessive capabilities (cap_sys_admin, cap_sys_ptrace, cap_sys_module)
		capabilities=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- capsh --print 2>/dev/null)
		# TODO add a check here to detect no capsh, and then try to install it before running again.
		if [[ "$capabilities" =~ "cap_sys_admin\|cap_sys_ptrace\|cap_sys_module" ]] ; then
			echo "!!! $pod has dangerous capabilities (capsh --print) (cap_sys_admin, cap_sys_ptrace, cap_sys_module)!!!" | tee -a issues.txt
		fi

		# Checking for root
		user=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- whoami 2>/dev/null)
		if [[ "$user" =~ "root" ]] ; then
			echo "! $pod is running as root!" | tee -a issues.txt
		fi

		# pod token checks
		# get pod token
		temp_token=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- cat /run/secrets/kubernetes.io/serviceaccount/token)
		pod_namespace=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- cat /run/secrets/kubernetes.io/serviceaccount/namespace)

# TYPE: Privilege Escalation Checks	
	# kube-system NAMESPACE
		# list secrets (yes/no)
		# get clusterrolebindings (yes/no)

		answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i create clusterrolebindings 2>/dev/null)
		if [[ "$answer" =~ "yes" ]] ; then
			echo "!!! $pod serviceaccount token can create clusterrolebindings!!!" | tee -a issues.txt
		fi

		# loop through and do priv esc checks in each namespace
		namespace_array=("kube-system" "default" "$pod_namespace")
		for temp_namespace in "${namespace_array[@]}" ; do

			answer_temp=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i --list -n $temp_namespace 2>/dev/null | grep -v "selfsubjectaccessreviews\|selfsubjectrulesreviews")
			answer=$(echo "$answer_temp" | grep -i "create\|delete\|update\|patch")
			answer="$answer\n$(echo "$answer_temp" | grep -F '[*]')"
			answer_length=$(echo -n "$answer" | wc -l | sed 's/ //g')
			if [[ "$answer_length" -gt 0 ]] ; then
				echo "$pod permissions:" | tee -a interesting-permissions.txt
				echo "$answer" | tee -a interesting-permissions.txt
				echo "" | tee -a interesting-permissions.txt
			fi

			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i list secrets -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can list secrets in $temp_namespace!!!" | tee -a issues.txt
			fi
			# create pods (yes/no)
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i create pods -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can create pods in $temp_namespace!!!" | tee -a issues.txt
			fi
			# get pods in kube-system
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i get pods -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can get pods in $temp_namespace!!!" | tee -a issues.txt
			fi
			# delete pods in kube-system
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i delete pods -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can delete pods in $temp_namespace!!!" | tee -a issues.txt
			fi
			# get services in kube-system
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i get services -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can get services in $temp_namespace!!!" | tee -a issues.txt
			fi
			# get nodes in kube-system
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i get nodes -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can get nodes in $temp_namespace!!!" | tee -a issues.txt
			fi
			# get deployments in kube-system
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i get deployments -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can get deployments in $temp_namespace!!!" | tee -a issues.txt
			fi
			# get daemonsets in kube-system
			answer=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token auth can-i get daemonsets -n $temp_namespace 2>/dev/null)
			if [[ "$answer" =~ "yes" ]] ; then
				echo "!!! $pod serviceaccount token can get daemonsets in $temp_namespace!!!" | tee -a issues.txt
			fi
		done 

		# grab and search environment variables
		environmentvars=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- env 2>/dev/null)
		lines=$(echo "$environmentvars" | grep -i "pass\|user\|aws\|AKIA\|secret\|access\|token\|key" | wc -l | sed 's/ //g')
		if [[ "$lines" -gt 0 ]] ; then
			echo "$pod env:" | tee -a interesting-env.txt
			echo "$environmentvars" | grep -i "pass\|user\|aws\|AKIA\|secret\|access\|token\|key" | tee -a interesting-env.txt
			echo "" | tee -a interesting-env.txt
		fi

# TYPE: Looting secrets
		# check for mouthpaths in the yaml and search them for secrets
		mountpaths=$(echo "$yaml" | grep "mountPath" | grep -v "/var/run/secrets/kube" | sed 's/  */ /g' | cut -d ' ' -f 4-)
		for mount_path in $(echo $mountpaths); do
			output=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- bash -c "grep -irn \"pass\|user\|aws\|AKIA\|secret\|access\|token\|key\" \"$mount_path\"")
			if [[ ! -z "$output" ]] ; then
				echo "$pod mounts ($mount_path):" | tee -a interesting-mounts.txt
				echo $output | tee -a interesting-mounts.txt
			fi
		done

		# grab and search bash historys
		kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- bash -c "find / -name .bash_history 2>/dev/null" 2>/dev/null > bash_history_locations.txt 
		for bash_history in $(cat bash_history_locations.txt); do
			bash_history_contents=$(kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- cat $bash_history 2>/dev/null)
			lines=$(echo "$bash_history_contents" | grep -i "pass\|user\|aws\|AKIA\|secret\|access\|token\|key" | wc -l | sed 's/ //g')
			if [[ "$lines" -gt 0 ]] ; then
				echo "$pod bash history:" | tee -a interesting-history.txt
				echo "$bash_history_contents" | grep -i "pass\|user\|aws\|AKIA\|secret\|access\|token\|key" | tee -a interesting-history.txt
				echo "" | tee -a interesting-history.txt
			fi
		done
		rm bash_history_locations.txt

		# List and grep through the secrets available
		kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token get secrets -n $pod_namespace 2>/dev/null | sed 's/  */ /g' | cut -d ' ' -f 1,2 | tail -n +2 > secrets_list.txt 
		for secret in $(cat secrets_list.txt); do
			secret_name=$(echo $secret | cut -d ' ' -f 1)
			secret_type=$(echo $secret | cut -d ' ' -f 2)

			exists="0"

			# check we havent already recorded the secret, if so set exists to 1 so we skip recording it
			for existing_secret in $secret_array; do
				if [[ "$existing_secret" == "${secret_name}" ]]; then
					exists="1"
				fi
			done
			#if [[ " ${secret_array[@]} " == "${secret_name}" ]]; then
			#if printf '%s\n' "${secret_array[@]}" | grep -q -P '^secret_name$'; then
			if [[ "$exists" == "0" ]]; then
				# if the secret hasn't been stored then we grab it and then store it as completed
				echo "Secret - $secret_name - ($secret_type)" | tee -a secrets.txt
				# we dont print the whole secret in terminal because its too spammy 
				kubectl $context1 $context2 $namespace1 $namespace2 exec $pod -- /tmp/kubectl --token=$temp_token get secret $secret_name -o json | jq -r '.data | map_values(@base64d)' >> secrets.txt
				secret_array+=("$secret_name")
			fi
		done
	fi
done

